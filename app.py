import csv
import glob
import io
import json
import os
import pickle
import sqlite3
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

LOG_DIRS = [
    os.path.expanduser("~/kismet-logs"),
    os.path.expanduser("~/wardriver/kismet-logs"),
]

_file_cache   = {}
_device_cache = None
_cache_lock   = threading.Lock()

DISK_CACHE_FILE = os.path.expanduser("~/.wardriver_cache.pkl")


def _load_disk_cache():
    try:
        with open(DISK_CACHE_FILE, "rb") as f:
            return pickle.load(f)
    except Exception:
        return {"csv": {}, "kismet": {}}


def _save_disk_cache(dc):
    try:
        with open(DISK_CACHE_FILE, "wb") as f:
            pickle.dump(dc, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception as e:
        print(f"disk cache write error: {e}")


def classify_encryption(crypt_string):
    c = (crypt_string or "").upper()
    if "WPA3" in c: return "WPA3"
    if "WPA2" in c: return "WPA2"
    if "WPA"  in c: return "WPA"
    if "WEP"  in c: return "WEP"
    return "Open"


def band_of(ch):
    try:
        n = int(ch)
        if n <= 14:  return "2.4"
        if n <= 165: return "5"
        return "6"
    except (ValueError, TypeError):
        return None


def iter_files(ext):
    seen = set()
    for d in LOG_DIRS:
        for p in glob.glob(os.path.join(d, f"*.{ext}")) + \
                 glob.glob(os.path.join(d, f"*/*.{ext}")):
            if p not in seen:
                seen.add(p)
                yield p


def parse_wiglecsv_full(path):
    """Single-pass parse: returns (gps_dict, track_list).
    gps_dict: {mac: (lat, lon, rssi, ch, seen)}
    track_list: [(epoch, lat, lon)]
    """
    gps   = {}
    track = []
    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return gps, track

    data   = [l for l in lines if not l.startswith("WigleWifi")]
    reader = csv.DictReader(io.StringIO("".join(data)))
    for row in reader:
        mac = (row.get("MAC") or "").strip()
        if not mac:
            continue
        try:
            lat = float(row.get("CurrentLatitude")  or 0)
            lon = float(row.get("CurrentLongitude") or 0)
        except ValueError:
            continue
        if not lat or not lon:
            continue
        try:
            rssi = int(row.get("RSSI") or 0)
        except ValueError:
            rssi = 0
        ch   = (row.get("Channel")   or "").strip()
        seen = (row.get("FirstSeen") or "").strip()

        if mac not in gps or rssi > gps[mac][2]:
            gps[mac] = (lat, lon, rssi, ch, seen)

        if seen:
            try:
                epoch = datetime.strptime(seen, "%Y-%m-%d %H:%M:%S").timestamp()
                track.append((epoch, lat, lon))
            except ValueError:
                pass

    # deduplicate + downsample track per file before caching
    if track:
        track.sort(key=lambda x: x[0])
        deduped = [track[0]]
        for pt in track[1:]:
            if abs(pt[1]-deduped[-1][1]) > 1e-5 or abs(pt[2]-deduped[-1][2]) > 1e-5:
                deduped.append(pt)
        step = max(1, len(deduped) // 2000)
        track = deduped[::step]

    return gps, track


def build_track_from_pts(raw):
    """Convert sorted (epoch, lat, lon) list into polyline segments."""
    if not raw:
        return []
    raw.sort(key=lambda x: x[0])

    deduped = [raw[0]]
    for pt in raw[1:]:
        _, plat, plon = deduped[-1]
        if abs(pt[1] - plat) > 1e-5 or abs(pt[2] - plon) > 1e-5:
            deduped.append(pt)

    segments = []
    seg = [deduped[0]]
    for i in range(1, len(deduped)):
        if deduped[i][0] - deduped[i-1][0] > 300:
            segments.append([[p[1], p[2]] for p in seg])
            seg = []
        seg.append(deduped[i])
    if seg:
        segments.append([[p[1], p[2]] for p in seg])

    total = sum(len(s) for s in segments)
    if total > 3000:
        step = max(1, total // 3000)
        segments = [s[::step] for s in segments]

    return segments


def parse_kismet_db(path):
    """Return {mac: {ssid, enc, crypt, type}} from a .kismet SQLite file."""
    out = {}
    try:
        db  = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        cur = db.cursor()
        cur.execute("SELECT device FROM devices")
    except Exception:
        return out

    for (raw,) in cur:
        try:
            d = json.loads(raw)
        except Exception:
            continue
        mac = d.get("kismet.device.base.macaddr", "").strip()
        if not mac:
            continue
        dev_type = d.get("kismet.device.base.type", "").strip()
        is_bt    = "bluetooth" in dev_type.lower()
        dot11    = d.get("dot11.device", {})
        ssid_rec = dot11.get("dot11.device.last_beaconed_ssid_record", {})
        ssid     = (ssid_rec.get("dot11.advertisedssid.ssid") or "").strip() or "(hidden)"
        crypt    = ssid_rec.get("dot11.advertisedssid.crypt_string", "") or ""
        enc      = "BT" if is_bt else classify_encryption(crypt)
        if mac not in out or (crypt and not out[mac]["crypt"]):
            out[mac] = {"ssid": ssid, "enc": enc, "crypt": crypt, "type": dev_type}

    db.close()
    return out


def rebuild_cache():
    global _file_cache, _device_cache

    csv_files    = sorted(iter_files("wiglecsv"))
    kismet_files = sorted(iter_files("kismet"))

    # load per-file disk cache
    dc        = _load_disk_cache()
    csv_dc    = dc.get("csv",    {})
    kismet_dc = dc.get("kismet", {})
    dc_dirty  = False

    # find files missing from or changed since disk cache
    csv_missing    = [p for p in csv_files    if csv_dc.get(p,    (None,))[0] != _safe_mtime(p)]
    kismet_missing = [p for p in kismet_files if kismet_dc.get(p, (None,))[0] != _safe_mtime(p)]

    if not csv_missing and not kismet_missing and _device_cache is not None:
        return  # nothing changed, memory cache still valid

    # parse only new/changed CSV files
    if csv_missing:
        with ThreadPoolExecutor(max_workers=4) as ex:
            for path, (gps, track) in zip(csv_missing, ex.map(parse_wiglecsv_full, csv_missing)):
                m = _safe_mtime(path)
                if m:
                    csv_dc[path] = (m, gps, track)
                    dc_dirty = True

    # parse only new/changed kismet files
    if kismet_missing:
        with ThreadPoolExecutor(max_workers=4) as ex:
            for path, enc in zip(kismet_missing, ex.map(parse_kismet_db, kismet_missing)):
                m = _safe_mtime(path)
                if m:
                    kismet_dc[path] = (m, enc)
                    dc_dirty = True

    if dc_dirty:
        _save_disk_cache({"csv": csv_dc, "kismet": kismet_dc})

    # merge from disk cache
    gps_data  = {}
    all_track = []
    for p in csv_files:
        if p not in csv_dc:
            continue
        _, gps, track = csv_dc[p]
        for mac, val in gps.items():
            if mac not in gps_data or val[2] > gps_data[mac][2]:
                gps_data[mac] = val
        all_track.extend(track)

    enc_data = {}
    for p in kismet_files:
        if p not in kismet_dc:
            continue
        _, enc = kismet_dc[p]
        for mac, val in enc.items():
            if mac not in enc_data or (val["crypt"] and not enc_data[mac]["crypt"]):
                enc_data[mac] = val

    # merge
    all_macs = set(gps_data) | set(enc_data)
    devices  = []
    for mac in all_macs:
        g = gps_data.get(mac)
        e = enc_data.get(mac, {})
        lat, lon, rssi, ch, seen = g if g else (0.0, 0.0, 0, "", "")
        devices.append({
            "mac":   mac,
            "ssid":  e.get("ssid", "(hidden)"),
            "enc":   e.get("enc",  "Open"),
            "crypt": e.get("crypt", ""),
            "seen":  seen,
            "ch":    ch,
            "rssi":  rssi,
            "lat":   lat,
            "lon":   lon,
            "type":  e.get("type", ""),
        })

    wifi    = [d for d in devices if d["enc"] != "BT"]
    bt_devs = [d for d in devices if d["enc"] == "BT"]
    enc_counts = dict(Counter(d["enc"] for d in devices))

    # channel distribution (wifi only)
    channel_counts = {}
    for d in wifi:
        ch = (d.get("ch") or "").strip()
        if ch:
            channel_counts[ch] = channel_counts.get(ch, 0) + 1

    # RSSI histogram (5dBm buckets)
    rssi_hist = {}
    for d in devices:
        r = d.get("rssi", 0)
        if r:
            bucket = (r // 5) * 5
            key = str(bucket)
            rssi_hist[key] = rssi_hist.get(key, 0) + 1

    # top SSIDs (exclude hidden)
    ssid_enc_map = {}
    for d in devices:
        s = d["ssid"]
        if s not in ssid_enc_map:
            ssid_enc_map[s] = d["enc"]
    ssid_counter = Counter(d["ssid"] for d in devices if d["ssid"] != "(hidden)")
    top_ssids = [
        {"ssid": s, "n": n, "enc": ssid_enc_map.get(s, "Open")}
        for s, n in ssid_counter.most_common(15)
    ]

    # band counts
    band_counts = {}
    for d in wifi:
        b = band_of(d.get("ch"))
        if b:
            band_counts[b] = band_counts.get(b, 0) + 1

    result = {
        "total":          len(devices),
        "bt_count":       len(bt_devs),
        "open_count":     enc_counts.get("Open", 0),
        "session_count":  len(csv_files),
        "enc_counts":     enc_counts,
        "band_counts":    band_counts,
        "channel_counts": channel_counts,
        "rssi_hist":      rssi_hist,
        "top_ssids":      top_ssids,
        "track":          build_track_from_pts(all_track),
        "devices":        [d for d in devices if d["lat"] and d["lon"]],
    }

    with _cache_lock:
        _file_cache   = {p: _safe_mtime(p) for p in csv_files + kismet_files}
        _device_cache = result


def _safe_mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def background_refresher():
    while True:
        try:
            rebuild_cache()
        except Exception as e:
            print(f"cache refresh error: {e}")
        time.sleep(60)


threading.Thread(target=background_refresher, daemon=True).start()


@app.route("/api/devices")
def api_devices():
    with _cache_lock:
        data = _device_cache
    if data is None:
        return jsonify({"loading": True, "total": 0, "bt_count": 0, "open_count": 0,
                        "session_count": 0, "enc_counts": {}, "band_counts": {},
                        "channel_counts": {}, "rssi_hist": {}, "top_ssids": [],
                        "track": [], "devices": []})
    return jsonify(data)


PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Wardriver</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.css"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.Default.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js"></script>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:      #0d1109;
  --panel:   #131a10;
  --surface: #192116;
  --border:  #253320;
  --text:    #bfcdb3;
  --sub:     #6a8460;
  --moss:    #4a6a3a;
  --accent:  #7aaa60;

  --wpa3:  #7ac870;
  --wpa2:  #c8a840;
  --wpa:   #e08030;
  --wep:   #c84848;
  --open:  #5a9a8a;
  --bt:    #9870c0;
}

html, body { height: 100%; }
body {
  background: var(--bg); color: var(--text);
  font-family: 'Segoe UI', system-ui, sans-serif; font-size: 12px;
  display: flex; flex-direction: column;
}

/* ── header ── */
header {
  background: var(--panel);
  border-bottom: 1px solid var(--border);
  padding: .4rem .9rem;
  display: flex; align-items: center; gap: 1.2rem; flex-shrink: 0;
}
.hdr-title h1 {
  font-size: .88rem; font-weight: 800; letter-spacing: .12em;
  text-transform: uppercase; color: var(--accent);
}
.hdr-title p { font-size: .68rem; color: var(--sub); margin-top: .05rem; }

.hdr-stats { display: flex; gap: .9rem; margin-left: auto; }
.hdr-stat  { text-align: right; }
.hdr-stat .n   { font-size: 1.2rem; font-weight: 700; line-height: 1; }
.hdr-stat .lbl { font-size: .6rem; text-transform: uppercase; letter-spacing: .1em; color: var(--sub); }
.hdr-divider { width: 1px; background: var(--border); align-self: stretch; margin: .1rem 0; }

#loading-bar {
  display: none; position: fixed; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, var(--moss), var(--accent));
  animation: slide 1.2s ease-in-out infinite; z-index: 9999;
}
@keyframes slide { 0%{transform:translateX(-100%)} 100%{transform:translateX(100%)} }

/* ── layout ── */
.body { display: flex; flex: 1; overflow: hidden; }

/* ── sidebar ── */
aside {
  width: 230px; flex-shrink: 0;
  background: var(--panel); border-right: 1px solid var(--border);
  display: flex; flex-direction: column; overflow-y: auto; overflow-x: hidden;
}
aside::-webkit-scrollbar { width: 3px; }
aside::-webkit-scrollbar-thumb { background: var(--border); }

.sb-section { padding: .55rem .75rem; border-bottom: 1px solid var(--border); }
.sb-section h2 {
  font-size: .6rem; text-transform: uppercase; letter-spacing: .14em;
  color: var(--sub); margin-bottom: .45rem;
}

/* ── donut chart ── */
#donut-wrap { position: relative; text-align: center; }
#donut-svg  { width: 120px; height: 120px; display: block; margin: 0 auto .4rem; }
.donut-center {
  position: absolute; top: 50%; left: 50%;
  transform: translate(-50%, -63%);
  text-align: center; pointer-events: none;
}
.donut-center .big { font-size: .96rem; font-weight: 700; color: var(--text); line-height: 1; }
.donut-center .sm  { font-size: .6rem; color: var(--sub); }
.enc-legend { display: flex; flex-direction: column; gap: .18rem; }
.enc-row {
  display: flex; align-items: center; gap: .35rem; cursor: pointer;
  padding: .1rem .2rem; border-radius: 2px; transition: background .12s;
  user-select: none;
}
.enc-row:hover { background: var(--surface); }
.enc-row.off .enc-dot { opacity: .25; }
.enc-row.off .enc-name, .enc-row.off .enc-n { color: var(--sub); opacity: .5; }
.enc-dot  { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.enc-name { flex: 1; font-size: .78rem; color: var(--text); }
.enc-n    { font-size: .7rem; color: var(--sub); }

/* ── bar charts (channels + rssi) ── */
.bar-chart { display: flex; flex-direction: column; gap: 2px; }
.bar-row   { display: flex; align-items: center; gap: .3rem; }
.bar-lbl   { width: 28px; font-size: .64rem; color: var(--sub); text-align: right; flex-shrink: 0; }
.bar-outer { flex: 1; height: 7px; background: var(--surface); border-radius: 2px; overflow: hidden; }
.bar-fill  { height: 100%; border-radius: 2px; }
.bar-n     { width: 28px; font-size: .64rem; color: var(--sub); flex-shrink: 0; }

/* ── top SSIDs ── */
.ssid-list { display: flex; flex-direction: column; gap: .22rem; }
.ssid-item { display: flex; align-items: center; gap: .35rem; }
.ssid-dot  { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.ssid-name { flex: 1; font-size: .75rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text); }
.ssid-n    { font-size: .68rem; color: var(--sub); flex-shrink: 0; }

/* ── map controls ── */
.map-ctrl { display: flex; flex-direction: column; gap: .3rem; }
.ctrl-row {
  display: flex; align-items: center; gap: .4rem;
  cursor: pointer; user-select: none; font-size: .78rem; color: var(--sub);
}
.ctrl-box {
  width: 13px; height: 13px; border-radius: 2px; border: 2px solid var(--border);
  flex-shrink: 0; display: flex; align-items: center; justify-content: center;
  background: transparent; transition: background .15s, border-color .15s;
}
.ctrl-row.on .ctrl-box { background: var(--sub); border-color: transparent; }
.ctrl-row.on .ctrl-box::after {
  content: ''; width: 5px; height: 3px;
  border-left: 2px solid var(--bg); border-bottom: 2px solid var(--bg);
  transform: rotate(-45deg) translateY(-1px);
}
.ctrl-track-line { width: 18px; height: 3px; border-radius: 2px; background: #e09050; opacity: .7; }

/* ── map ── */
#map-wrap { flex: 1; position: relative; }
#map { width: 100%; height: 100%; }

/* map legend (floating) */
#map-legend {
  position: absolute; bottom: 20px; right: 10px; z-index: 999;
  background: rgba(13,17,9,.88); border: 1px solid var(--border);
  border-radius: 4px; padding: .5rem .65rem;
  backdrop-filter: blur(4px);
}
#map-legend h3 { font-size: .58rem; text-transform: uppercase; letter-spacing: .12em; color: var(--sub); margin-bottom: .35rem; }
.leg-row { display: flex; align-items: center; gap: .35rem; margin-bottom: .22rem; }
.leg-dot  { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.leg-name { font-size: .74rem; color: var(--text); }

/* cluster overrides */
.marker-cluster-small, .marker-cluster-medium, .marker-cluster-large {
  background-color: rgba(30,50,20,0.7) !important;
}
.marker-cluster-small div, .marker-cluster-medium div, .marker-cluster-large div {
  background-color: rgba(74,106,58,0.88) !important;
  color: #bfcdb3 !important; font-weight: 700; font-size: 11px;
}

/* popup */
.leaflet-popup-content-wrapper {
  background: #192116; color: var(--text); border: 1px solid var(--border);
  border-radius: 5px; box-shadow: 0 4px 20px rgba(0,0,0,.6);
  font-size: .78rem; font-family: inherit;
}
.leaflet-popup-tip { background: #192116; }
.popup-title { font-weight: 700; font-size: .84rem; margin-bottom: .35rem; }
.popup-row   { display: flex; gap: .5rem; color: var(--sub); line-height: 1.8; }
.popup-row b { color: var(--text); min-width: 50px; }
.badge {
  display: inline-block; font-size: .58rem; font-weight: 700;
  padding: 1px 5px; border-radius: 2px; margin-right: 4px; letter-spacing: .04em;
}
.rssi-bar-popup { height: 4px; border-radius: 2px; margin-top: .25rem; }
</style>
</head>
<body>
<div id="loading-bar"></div>

<header>
  <div class="hdr-title">
    <h1>Wardriver</h1>
    <p id="hdr-sub">loading...</p>
  </div>
  <div class="hdr-stats">
    <div class="hdr-stat">
      <div class="n" id="s-total" style="color:var(--text)">--</div>
      <div class="lbl">Total Devices</div>
    </div>
    <div class="hdr-divider"></div>
    <div class="hdr-stat">
      <div class="n" id="s-open" style="color:var(--open)">--</div>
      <div class="lbl">Open Networks</div>
    </div>
    <div class="hdr-divider"></div>
    <div class="hdr-stat">
      <div class="n" id="s-bt" style="color:var(--bt)">--</div>
      <div class="lbl">Bluetooth</div>
    </div>
  </div>
</header>

<div class="body">
  <aside>

    <!-- encryption donut -->
    <div class="sb-section">
      <h2>Encryption</h2>
      <div id="donut-wrap">
        <svg id="donut-svg" viewBox="-1 -1 2 2" xmlns="http://www.w3.org/2000/svg"></svg>
        <div class="donut-center">
          <div class="big" id="donut-total">--</div>
          <div class="sm">networks</div>
        </div>
      </div>
      <div class="enc-legend" id="enc-legend"></div>
    </div>

    <!-- channel distribution -->
    <div class="sb-section">
      <h2>Channels</h2>
      <div class="bar-chart" id="ch-chart"></div>
    </div>

    <!-- rssi histogram -->
    <div class="sb-section">
      <h2>Signal Strength (dBm)</h2>
      <div class="bar-chart" id="rssi-chart"></div>
    </div>

    <!-- top ssids -->
    <div class="sb-section">
      <h2>Top SSIDs</h2>
      <div class="ssid-list" id="top-ssids"></div>
    </div>

    <!-- map controls -->
    <div class="sb-section">
      <h2>Overlay</h2>
      <div class="map-ctrl">
        <div class="ctrl-row on" id="track-toggle">
          <div class="ctrl-box"></div>
          <div class="ctrl-track-line"></div>
          <span>Show route</span>
        </div>
      </div>
    </div>

  </aside>

  <div id="map-wrap">
    <div id="map"></div>
    <div id="map-legend">
      <h3>Encryption</h3>
    </div>
  </div>
</div>

<script>
const ENC = {
  WPA3: { color: '#7ac870' },
  WPA2: { color: '#c8a840' },
  WPA:  { color: '#e08030' },
  WEP:  { color: '#c84848' },
  Open: { color: '#5a9a8a' },
  BT:   { color: '#9870c0' },
};
const TRACK_COLOR = '#e09050';

// ── map ──
const lmap = L.map('map', { preferCanvas: true }).setView([28.206, -82.753], 13);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
  attribution: '&copy; <a href="https://carto.com">CARTO</a>',
  subdomains: 'abcd', maxZoom: 20,
}).addTo(lmap);

const cluster = L.markerClusterGroup({
  maxClusterRadius: 50, disableClusteringAtZoom: 17,
  chunkedLoading: true, chunkInterval: 100,
});
lmap.addLayer(cluster);

const trackLayer = L.layerGroup().addTo(lmap);

// ── state ──
let allDevices  = [];
let trackData   = [];
let showTrack   = true;
let fittedOnce  = false;
const activeEnc = new Set(Object.keys(ENC));
let encCounts   = {};

function isBT(d)     { return d.enc === 'BT'; }
function encColor(d) { return ENC[d.enc]?.color || '#888'; }

function rssiWidth(rssi) {
  return Math.max(4, Math.min(100, ((rssi + 90) / 60) * 100));
}
function rssiColor(rssi) {
  if (rssi >= -60) return '#7ac870';
  if (rssi >= -75) return '#c8a840';
  return '#c84848';
}

function visible(d) {
  return activeEnc.has(d.enc);
}

// ── track ──
function drawTrack() {
  trackLayer.clearLayers();
  if (!showTrack || !trackData.length) return;
  for (const seg of trackData) {
    if (seg.length < 2) continue;
    L.polyline(seg, { color: TRACK_COLOR, weight: 2, opacity: 0.5 }).addTo(trackLayer);
  }
}

document.getElementById('track-toggle').addEventListener('click', function() {
  showTrack = this.classList.toggle('on');
  drawTrack();
});

// ── map rebuild ──
function applyFilters() {
  cluster.clearLayers();
  const layers = [];
  for (const d of allDevices) {
    if (!visible(d) || !d.lat || !d.lon) continue;
    const color = encColor(d);
    const m = L.circleMarker([d.lat, d.lon], {
      radius: 5, color, fillColor: color, fillOpacity: 0.85, weight: 1,
    }).bindPopup(makePopup(d), { maxWidth: 270 });
    layers.push(m);
  }
  cluster.addLayers(layers);
}

// ── donut chart ──
let _lastEncCounts = {};
function drawDonut(counts) {
  _lastEncCounts = counts;
  const svg   = document.getElementById('donut-svg');
  const total = Object.values(counts).reduce((a,b)=>a+b, 0);
  document.getElementById('donut-total').textContent = total.toLocaleString();
  svg.innerHTML = '';

  let angle = -Math.PI / 2;
  const R = 0.82, r = 0.52;

  for (const [enc, n] of Object.entries(ENC)) {
    const count = counts[enc] || 0;
    if (!count) continue;
    const color  = ENC[enc].color;
    const active = activeEnc.has(enc);
    const sweep  = (count / total) * 2 * Math.PI;
    const end    = angle + sweep;
    const large  = sweep > Math.PI ? 1 : 0;

    const x1 = Math.cos(angle)*R, y1 = Math.sin(angle)*R;
    const x2 = Math.cos(end)*R,   y2 = Math.sin(end)*R;
    const x3 = Math.cos(end)*r,   y3 = Math.sin(end)*r;
    const x4 = Math.cos(angle)*r, y4 = Math.sin(angle)*r;

    const path = document.createElementNS('http://www.w3.org/2000/svg','path');
    path.setAttribute('d', `M${x1},${y1} A${R},${R} 0 ${large} 1 ${x2},${y2} L${x3},${y3} A${r},${r} 0 ${large} 0 ${x4},${y4} Z`);
    path.setAttribute('fill', active ? color : '#2a3522');
    path.setAttribute('stroke', '#0d1109');
    path.setAttribute('stroke-width', '0.04');
    path.style.cursor = 'pointer';
    path.addEventListener('click', () => toggleEnc(enc));
    svg.appendChild(path);
    angle = end;
  }
}

function toggleEnc(enc) {
  if (activeEnc.has(enc)) activeEnc.delete(enc); else activeEnc.add(enc);
  drawDonut(_lastEncCounts);
  buildEncLegend(_lastEncCounts);
  applyFilters();
}

function buildEncLegend(counts) {
  const leg = document.getElementById('enc-legend');
  leg.innerHTML = '';
  for (const [enc, meta] of Object.entries(ENC)) {
    const n = counts[enc] || 0;
    if (!n) continue;
    const on  = activeEnc.has(enc);
    const row = document.createElement('div');
    row.className = 'enc-row' + (on ? '' : ' off');
    row.innerHTML = `
      <div class="enc-dot" style="background:${meta.color}"></div>
      <span class="enc-name">${enc}</span>
      <span class="enc-n">${n.toLocaleString()}</span>`;
    row.addEventListener('click', () => toggleEnc(enc));
    leg.appendChild(row);
  }
}

// ── map legend ──
function buildMapLegend(counts) {
  const el = document.getElementById('map-legend');
  el.innerHTML = '<h3>Encryption</h3>';
  for (const [enc, meta] of Object.entries(ENC)) {
    if (!(counts[enc] || 0)) continue;
    const row = document.createElement('div');
    row.className = 'leg-row';
    row.innerHTML = `<div class="leg-dot" style="background:${meta.color}"></div><span class="leg-name">${enc}</span>`;
    el.appendChild(row);
  }
}

// ── channel bar chart ──
function buildChannelChart(chCounts) {
  const el = document.getElementById('ch-chart');
  el.innerHTML = '';
  const sorted = Object.entries(chCounts)
    .map(([ch, n]) => [ch, n])
    .sort((a, b) => {
      const na = parseInt(a[0]) || 999, nb = parseInt(b[0]) || 999;
      return na - nb;
    });
  if (!sorted.length) return;
  const max = Math.max(...sorted.map(([,n])=>n));
  const BAND_COLOR = { '2.4': '#5a9a8a', '5': '#c8a840', '6': '#9870c0' };

  for (const [ch, n] of sorted) {
    let b = 'other';
    const ni = parseInt(ch);
    if (ni <= 14)  b = '2.4';
    else if (ni <= 165) b = '5';
    else b = '6';
    const color = BAND_COLOR[b] || '#6a8460';
    const pct = (n / max * 100).toFixed(0);
    const row = document.createElement('div');
    row.className = 'bar-row';
    row.innerHTML = `
      <span class="bar-lbl">${ch}</span>
      <div class="bar-outer"><div class="bar-fill" style="width:${pct}%;background:${color}"></div></div>
      <span class="bar-n">${n}</span>`;
    el.appendChild(row);
  }
}

// ── RSSI histogram ──
function buildRssiChart(hist) {
  const el = document.getElementById('rssi-chart');
  el.innerHTML = '';
  const sorted = Object.entries(hist)
    .map(([k, n]) => [parseInt(k), n])
    .sort((a, b) => b[0] - a[0]);
  if (!sorted.length) return;
  const max = Math.max(...sorted.map(([,n])=>n));

  for (const [bucket, n] of sorted) {
    const color = rssiColor(bucket);
    const pct   = (n / max * 100).toFixed(0);
    const row   = document.createElement('div');
    row.className = 'bar-row';
    row.innerHTML = `
      <span class="bar-lbl">${bucket}</span>
      <div class="bar-outer"><div class="bar-fill" style="width:${pct}%;background:${color}"></div></div>
      <span class="bar-n">${n}</span>`;
    el.appendChild(row);
  }
}

// ── top SSIDs ──
function buildTopSsids(ssids) {
  const el = document.getElementById('top-ssids');
  el.innerHTML = '';
  const max = ssids[0]?.n || 1;
  for (const { ssid, n, enc } of ssids) {
    const color = ENC[enc]?.color || BT_COLOR;
    const item  = document.createElement('div');
    item.className = 'ssid-item';
    item.innerHTML = `
      <div class="ssid-dot" style="background:${color}"></div>
      <span class="ssid-name" title="${ssid}">${ssid}</span>
      <span class="ssid-n">${n}</span>`;
    el.appendChild(item);
  }
}

function makePopup(d) {
  const c  = encColor(d);
  const w  = rssiWidth(d.rssi).toFixed(0);
  const rc = rssiColor(d.rssi);
  return `<div class="popup-title"><span class="badge" style="background:${c}22;color:${c}">${d.enc}</span>${d.ssid}</div>
  <div class="popup-row"><b>MAC</b><span style="font-family:monospace">${d.mac}</span></div>
  <div class="popup-row"><b>Cipher</b><span>${d.crypt || '--'}</span></div>
  <div class="popup-row"><b>Channel</b><span>${d.ch || '--'}</span></div>
  <div class="popup-row"><b>RSSI</b><span>${d.rssi} dBm</span></div>
  <div class="rssi-bar-popup" style="width:${w}%;max-width:180px;background:${rc}"></div>
  <div class="popup-row" style="margin-top:.3rem"><b>Seen</b><span>${d.seen || '--'}</span></div>`;
}

// ── data load ──
let isLoading = false;

async function load(showBar) {
  if (isLoading) return;
  isLoading = true;
  if (showBar) document.getElementById('loading-bar').style.display = 'block';
  try {
    const data = await fetch('/api/devices').then(r => r.json());
    if (data.loading) {
      setTimeout(() => { isLoading = false; load(true); }, 3000);
      return;
    }

    allDevices = data.devices;
    trackData  = data.track || [];

    document.getElementById('s-total').textContent = data.total.toLocaleString();
    document.getElementById('s-open').textContent  = (data.open_count || 0).toLocaleString();
    document.getElementById('s-bt').textContent    = (data.bt_count   || 0).toLocaleString();
    document.getElementById('hdr-sub').textContent =
      `${data.total.toLocaleString()} unique networks across ${data.session_count || 0} sessions`;

    encCounts = data.enc_counts || {};
    drawDonut(encCounts);
    buildEncLegend(encCounts);
    buildMapLegend(encCounts);
    buildChannelChart(data.channel_counts || {});
    buildRssiChart(data.rssi_hist || {});
    buildTopSsids(data.top_ssids || []);

    if (!fittedOnce) {
      const pts = allDevices.filter(d => d.lat && d.lon);
      if (pts.length) {
        lmap.fitBounds(L.latLngBounds(pts.map(d => [d.lat, d.lon])).pad(0.05));
        fittedOnce = true;
      }
    }

    drawTrack();
    applyFilters();
  } finally {
    isLoading = false;
    document.getElementById('loading-bar').style.display = 'none';
  }
}

load(true);
setInterval(() => load(false), 60000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
