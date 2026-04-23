#!/bin/bash

################################################################################
#                                                                              #
#  wardriver setup — kismet + gps map tracking                                #
#  works on: xubuntu, raspberry pi os, debian-based systems                   #
#                                                                              #
################################################################################

set -e

GREEN="\e[32m"
RESET="\e[0m"
log() { echo -e "${GREEN}==>${RESET} $1"; }

if ! command -v apt &>/dev/null; then
    echo "this script is for debian/ubuntu based systems only."
    exit 1
fi

log "updating package lists..."
sudo apt update

# -----------------------------
# KISMET
# -----------------------------
log "installing kismet dependencies..."
sudo apt install -y \
    build-essential \
    git \
    pkg-config \
    libwebsockets-dev \
    libpcap-dev \
    libnl-3-dev \
    libnl-genl-3-dev \
    libcap-dev \
    libpcre2-dev \
    libsqlite3-dev \
    libprotobuf-dev \
    libprotobuf-c-dev \
    protobuf-compiler \
    protobuf-c-compiler \
    libsensors-dev \
    libusb-1.0-0-dev \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-protobuf \
    python3-requests \
    python3-numpy \
    python3-serial \
    python3-usb \
    python3-dev \
    gpsd \
    gpsd-clients \
    aircrack-ng \
    iw \
    wireless-tools \
    net-tools \
    curl \
    wget \
    gpsprune \
    sqlitebrowser 2>/dev/null || true

log "adding kismet apt repository..."
RELEASE=$(lsb_release -cs 2>/dev/null || echo "jammy")

curl -s https://www.kismetwireless.net/repos/kismet-release.gpg.key \
    | gpg --dearmor \
    | sudo tee /usr/share/keyrings/kismet-archive-keyring.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/${RELEASE} ${RELEASE} main" \
    | sudo tee /etc/apt/sources.list.d/kismet.list

sudo apt update
sudo apt install -y kismet

# -----------------------------
# USER GROUPS
# -----------------------------
log "adding $USER to kismet group..."
sudo usermod -aG kismet "$USER"

# -----------------------------
# GPS SETUP
# -----------------------------
log "configuring gpsd..."

# detect GPS device — u-blox shows as ttyACM0, others as ttyUSB0
GPS_DEV=""
for dev in /dev/ttyACM0 /dev/ttyUSB0; do
    if [ -e "$dev" ]; then
        GPS_DEV="$dev"
        log "found GPS at $dev"
        break
    fi
done

if [ -z "$GPS_DEV" ]; then
    GPS_DEV="/dev/ttyACM0"
    log "GPS not detected yet — defaulting to /dev/ttyACM0 (plug in before starting)"
fi

sudo tee /etc/default/gpsd > /dev/null <<EOF
START_DAEMON="true"
USBAUTO="true"
DEVICES="$GPS_DEV"
GPSD_OPTIONS="-n"
EOF

sudo systemctl enable gpsd
sudo systemctl restart gpsd || true

# -----------------------------
# KISMET CONFIG
# -----------------------------
log "setting up kismet config..."
mkdir -p "$HOME/.kismet"
mkdir -p "$HOME/kismet-logs"

cat > "$HOME/.kismet/kismet_site.conf" <<EOF
# wardriver kismet config

# log to home directory
log_prefix=$HOME/kismet-logs

# gps via gpsd
gps=gpsd:host=localhost,port=2947

# log formats
# kismet   = native format, full detail
# wiglecsv = upload to wigle.net
# pcapng   = packet capture
# gpx      = gps track file, open in any map app
log_types=kismet,wiglecsv,pcapng,gpx

# web ui accessible from any device on the network
httpd_bind_address=0.0.0.0
httpd_port=2501

# alert on new devices
EOF

# -----------------------------
# MONITOR MODE HELPERS
# -----------------------------
cat > "$HOME/monitor-on.sh" <<'EOF'
#!/bin/bash
IFACE=${1:-wlan0}
sudo ip link set "$IFACE" down
sudo iw dev "$IFACE" set type monitor
sudo ip link set "$IFACE" up
echo "monitor mode enabled on $IFACE"
iw dev "$IFACE" info | grep type
EOF
chmod +x "$HOME/monitor-on.sh"

cat > "$HOME/monitor-off.sh" <<'EOF'
#!/bin/bash
IFACE=${1:-wlan0}
sudo ip link set "$IFACE" down
sudo iw dev "$IFACE" set type managed
sudo ip link set "$IFACE" up
sudo systemctl restart NetworkManager 2>/dev/null || sudo systemctl restart networking
echo "managed mode restored on $IFACE"
EOF
chmod +x "$HOME/monitor-off.sh"

# -----------------------------
# GPX EXPORT SCRIPT
# -----------------------------
cat > "$HOME/export-map.sh" <<'EOF'
#!/bin/bash
# convert kismet .kismet db to gpx for viewing in any map app
# usage: ./export-map.sh [kismet-log-file.kismet]

LOG=${1:-$(ls -t ~/kismet-logs/*.kismet 2>/dev/null | head -1)}

if [ -z "$LOG" ]; then
    echo "no kismet log found. run kismet first."
    exit 1
fi

OUT="${LOG%.kismet}.gpx"

echo "exporting GPS track from $LOG..."

python3 <<PYEOF
import sqlite3, sys

log = "$LOG"
out = "$OUT"

try:
    db = sqlite3.connect(log)
    cur = db.cursor()

    # get GPS track points from kismet db
    cur.execute("""
        SELECT lat, lon, alt, CAST(ts_sec AS INTEGER)
        FROM devices
        WHERE lat != 0 AND lon != 0
        ORDER BY ts_sec
    """)
    rows = cur.fetchall()
    db.close()

    if not rows:
        print("no GPS data found in log.")
        sys.exit(1)

    with open(out, 'w') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<gpx version="1.1" creator="wardriver">\n')
        f.write('  <trk><name>wardriver session</name><trkseg>\n')
        for lat, lon, alt, ts in rows:
            f.write(f'    <trkpt lat="{lat}" lon="{lon}">\n')
            if alt:
                f.write(f'      <ele>{alt}</ele>\n')
            f.write(f'    </trkpt>\n')
        f.write('  </trkseg></trk>\n</gpx>\n')

    print(f"exported {len(rows)} points to {out}")
    print(f"open with: gpsprune {out}")

except Exception as e:
    print(f"error: {e}")
    sys.exit(1)
PYEOF
EOF
chmod +x "$HOME/export-map.sh"

# -----------------------------
# START SCRIPT
# -----------------------------
cat > "$HOME/start-wardriver.sh" <<'EOF'
#!/bin/bash
IFACE=${1:-wlan0}
echo "=== wardriver ==="
echo "interface: $IFACE"
echo ""

# check GPS
if cgps -s -l 2>/dev/null | grep -q "Status"; then
    echo "GPS: connected"
else
    echo "GPS: not detected — plug in u-blox and check ls /dev/ttyACM*"
fi

echo ""
echo "putting $IFACE into monitor mode..."
~/monitor-on.sh "$IFACE"

echo ""
echo "starting kismet..."
echo "web ui: http://localhost:2501"
echo "  (or from phone/laptop on same network)"
echo ""
echo "to stop: ctrl+c, then run ~/monitor-off.sh $IFACE"
echo ""

kismet -c "$IFACE"
EOF
chmod +x "$HOME/start-wardriver.sh"

# -----------------------------
# DONE
# -----------------------------
echo ""
echo -e "${GREEN}=====================================${RESET}"
echo " wardriver setup complete!"
echo ""
echo " quick start:"
echo "  1. log out and back in first"
echo "  2. plug in u-blox GPS"
echo "  3. ~/start-wardriver.sh wlan0"
echo "  4. open http://localhost:2501 in browser"
echo "     — live map shows networks as you drive"
echo ""
echo " after a session:"
echo "  ~/export-map.sh        — export GPS track to GPX"
echo "  gpsprune ~/kismet-logs/session.gpx  — view on map"
echo ""
echo " logs: ~/kismet-logs/"
echo "  *.kismet   — full data"
echo "  *.wiglecsv — upload to wigle.net"
echo "  *.gpx      — gps track"
echo -e "${GREEN}=====================================${RESET}"
echo ""
echo "IMPORTANT: log out and back in now for group permissions."
