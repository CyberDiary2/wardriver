# wardriver

kismet-based wardriving setup with a post-session dashboard for exploring captured data.  
works on: xubuntu, raspberry pi os, any debian-based system.

## hardware

- laptop or raspberry pi 4b
- **alfa network adapter** (AWUS036ACH or similar) — external antenna, monitor mode support
- u-blox 7 USB GPS antenna

## install

```bash
git clone https://github.com/CyberDiary2/wardriver.git
cd wardriver
chmod +x setup.sh
./setup.sh
```

then **log out and back in** for group permissions to take effect.

## quick start

plug in your alfa adapter and u-blox GPS, then:

```bash
~/start-wardriver.sh wlan0
```

open **http://localhost:2501** in your browser — kismet's live map shows networks as you drive.  
view from your phone or another laptop on the same network too.

## find your alfa interface name

```bash
iw dev
```

look for your alfa — it may be `wlan1` if you have a built-in wifi card too. use that name:

```bash
~/start-wardriver.sh wlan1
```

## GPS

the u-blox GPS plugs in via USB and shows up as `/dev/ttyACM0`.  
check it's working before you start:

```bash
cgps -s
```

wait 1-2 minutes outside for a fix. kismet will log GPS coordinates with every network found.

## dashboard

`app.py` is a Flask dashboard for exploring your captured data after a session.

**install dependencies:**

```bash
pip3 install flask
```

**run:**

```bash
python3 app.py
```

open **http://localhost:5050** in your browser.

the dashboard reads all `.kismet` and `.wiglecsv` files from `~/kismet-logs/` and `~/wardriver/kismet-logs/` automatically. it caches everything in memory and refreshes every 60 seconds.

**features:**

- interactive map with zoom-out clustering (CartoDB dark tiles)
- encryption donut chart — click segments to filter the map
- channel distribution bar chart (2.4 / 5 / 6 GHz color-coded)
- signal strength (RSSI) histogram
- top SSIDs list
- GPS route polyline overlay showing where you drove
- stats: total devices, open networks, bluetooth count, session count

encryption is read from the `.kismet` SQLite databases. GPS coordinates come from the `.wiglecsv` files. the two are joined by MAC address.

**during a session** — kismet's own web ui at http://localhost:2501 shows a live map

## upload to wigle.net

kismet automatically saves a `.wiglecsv` file in `~/kismet-logs/`.  
create a free account at [wigle.net](https://wigle.net) and upload it to add your data to the global wardriving map.

## logs

all logs saved to `~/kismet-logs/`:

| file | contents |
|------|----------|
| `.kismet` | full kismet database — all device detail |
| `.wiglecsv` | wigle.net upload format |
| `.pcapng` | packet capture — open in wireshark |
| `.gpx` | GPS track |

## manual monitor mode

```bash
~/monitor-on.sh wlan1    # enable monitor mode
~/monitor-off.sh wlan1   # restore normal wifi
```

## raspberry pi notes

same setup — just run `./setup.sh` on raspberry pi os.  
use VNC or plug in a monitor to view the kismet web ui,  
or access http://pi-ip:2501 from another device on the network.

## alfa adapter notes

the **AWUS036ACH** (dual band AC1200) is recommended — good range, well supported on linux.  
the **AWUS036ACH** needs the `rtl8812au` driver:

```bash
sudo apt install dkms
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install
```

reboot after installing the driver.
