# SNI-Spoofing-Pro
Bypass DPI with IP/TCP header manipulation.

## Fork Notice
This repository is the primary maintained fork for this project path in this account, based on the original upstream:

- Upstream: `patterniha/SNI-Spoofing`
- Upstream URL: https://github.com/patterniha/SNI-Spoofing

## Acknowledgment
Special thanks to **patterniha** for the original project and foundation.

## Donation
Support ongoing development:

- USDT (BEP20): `0x76a768B53Ca77B43086946315f0BDF21156bF424`
- USDT (TRC20): `TU5gKvKqcXPn8itp1DouBCwcqGHMemBm8o`
- Telegram: https://t.me/projectXhttp
- Telegram: https://t.me/patterniha

## Platform Model
- Windows: WinDivert (`pydivert`) injection path
- Linux (Ubuntu): active interception via `NFQUEUE` + `iptables` (not passive sniff-only)

## How It Works (Linux)
1. Outbound/inbound handshake packets are redirected into an `NFQUEUE`.
2. The outbound ACK is held in queue.
3. A fake TLS packet is injected using `wrong_seq`.
4. The original queued ACK is accepted right after fake send.
5. If expected ACK flow is observed, relay starts; otherwise connection is closed.

## Runtime Features
- Structured logging (`LOG_LEVEL`, optional `LOG_FILE`)
- Optional client SNI extraction + periodic top SNI stats (`LOG_CLIENT_SNI`, `STATS_INTERVAL`)
- Connection/IP accounting and bypass success/fail counters
- Rate limiting per client IP (`RATE_LIMIT`)
- Concurrent connection limit (`MAX_CONNECTIONS`)
- Per-direction idle timeout (`IDLE_TIMEOUT`)
- Accept-loop concurrency guard (`HANDLE_LIMIT`) and configurable backlog (`ACCEPT_BACKLOG`)
- Resource pressure backoff for socket pressure events (`RESOURCE_PRESSURE_BACKOFF`)
- Browser-like TLS fingerprint modes (`BROWSER_PROFILE`)
- Legacy ClientHello mode (`BROWSER_PROFILE=legacy`)
- Humanized fake-send delay (`FAKE_DELAY_MS`)
- Optional TTL spoofing for fake packet (`TTL_SPOOF`)
- Worker queue for fake packet sending (`FAKE_SEND_WORKERS`)
- NFQUEUE queue hardening (`NFQUEUE_MAXLEN`)
- Fail-open/fail-closed jump behavior (`NFQUEUE_FAIL_OPEN`)
- Narrow handshake-only or wider NFQUEUE rules (`NARROW_NFQUEUE_FILTER`)

## Requirements
### Ubuntu
```bash
sudo apt update
sudo apt install -y \
  python3 python3-pip python3-dev \
  build-essential libpcap-dev libnetfilter-queue-dev \
  iptables logrotate ca-certificates iputils-ping
pip3 install -r requirements.txt
```

### Python Dependencies
`requirements.txt` is platform-aware:
- Windows: `pydivert`
- Linux: `scapy`, `NetfilterQueue`

### Privileges
- Linux must run as `root` (`sudo`) for `iptables`, `NFQUEUE`, and raw packet injection.
- Windows path requires admin privileges and WinDivert availability.

## Configuration
All runtime options are loaded from `config.json`.

| Key | Default | Description |
|---|---|---|
| `LISTEN_HOST` | `127.0.0.1` | Local bind address for relay listener |
| `LISTEN_PORT` | `40443` | Local bind port |
| `CONNECT_IP` | `104.19.229.21` | Upstream destination IP |
| `CONNECT_PORT` | `443` | Upstream destination port |
| `FAKE_SNI` | `dashboard.hcaptcha.com` | Fake SNI hostname used in injected TLS ClientHello |
| `DATA_MODE` | `tls` | Data mode (currently only `tls`) |
| `BYPASS_METHOD` | `wrong_seq` | Bypass method (currently only `wrong_seq`) |
| `BYPASS_TIMEOUT` | `2.0` | Seconds to wait for bypass handshake completion |
| `CONNECT_TIMEOUT` | `5.0` | Upstream connect timeout (seconds) |
| `FAKE_DELAY_MS` | `1.0` | Base fake-send delay (ms), humanized internally |
| `BROWSER_PROFILE` | `random` | `legacy`, `random`, `chrome`, `firefox`, `safari`, `edge` |
| `TTL_SPOOF` | `true` | Randomized fake-packet TTL spoofing |
| `FAKE_SEND_WORKERS` | `2` | Number of fake-send worker threads |
| `NFQUEUE_NUM` | `1` | NFQUEUE number |
| `NFQUEUE_MAXLEN` | `4096` | Queue maxlen for NFQUEUE |
| `NFQUEUE_FAIL_OPEN` | `true` | Adds/removes `--queue-bypass` behavior |
| `NARROW_NFQUEUE_FILTER` | `true` | Handshake-focused rules when true, wider rules when false |
| `RECV_BUFFER` | `65536` | Socket receive buffer size |
| `MAX_CONNECTIONS` | `0` | Max active connections (`0` = unlimited) |
| `IDLE_TIMEOUT` | `0` | Idle timeout seconds (`0` = disabled) |
| `RATE_LIMIT` | `0` | New connections per second per source IP (`0` = disabled) |
| `HANDLE_LIMIT` | `256` | Concurrent handler semaphore limit |
| `ACCEPT_BACKLOG` | `256` | TCP listen backlog |
| `RESOURCE_PRESSURE_BACKOFF` | `0.5` | Backoff seconds under ENOBUFS/ENOMEM/FD pressure |
| `LOG_LEVEL` | `INFO` | Log level |
| `LOG_FILE` | empty | Optional file logging path |
| `LOG_CLIENT_SNI` | `true` | Enable SNI extraction from initial client TLS |
| `STATS_INTERVAL` | `60` | Periodic stats log interval (seconds, `<=0` disables loop) |

## Quick Run
### Linux
```bash
sudo python3 main.py
```

### Windows
```bash
python main.py
```

## Production Deployment (systemd)
Deployment assets:
- `deploy/sni-spoofing.service.template`
- `deploy/install-production.sh`
- `deploy/healthcheck.py`
- `deploy/logrotate-sni-spoofing.conf`
- `deploy/sni-manager.sh`
- `deploy/sni_target_scanner.py`
- `deploy/scanner_targets.txt`
- `deploy/build-offline-bundle.sh`

### Option A: Unified Manager (Recommended)
```bash
cd /path/to/SNI-Spoofing-Pro
chmod +x deploy/sni-manager.sh
sudo ./deploy/sni-manager.sh
```

Behavior:
- First run: installs packages/dependencies, deploys to `/opt/sni-spoofing`, installs systemd/logrotate, enables and starts service, then opens interactive menu.
- Next runs: verifies installation and opens the interactive menu directly.
- After config edits (wizard/manual), manager runs config validation plus target connectivity check automatically.

Manager menu operations:
1. Start service
2. Stop service
3. Restart service
4. Reset pipeline (cleanup NFQUEUE rules + restart)
5. Service status
6. Live journal logs
7. Recent logs + warnings
8. App log file recent tail
9. App log file live tail
10. Healthcheck
11. Config validation
12. Quick config wizard
13. Manual config edit
14. NFQUEUE tuning profiles
15. Show tagged NFQUEUE iptables rules
16. Cleanup tagged NFQUEUE iptables rules
17. Backup config
18. Restore latest config backup
19. Force logrotate
20. Upgrade/reinstall from current source
21. Uninstall
22. Connectivity check (DNS + ping + TCP)
23. Repair Python deps (NetfilterQueue/Scapy)
24. Run SNI scanner + apply best to config
25. Edit scanner targets list
26. Show latest scanner report

## Integrated SNI Scanner
This project now includes an integrated scanner inspired by `seramo/sni-scanner`, implemented directly inside this repository.

Files:
- `deploy/sni_target_scanner.py`
- `deploy/scanner_targets.txt`

What it does:
- reads domain/IP targets from `deploy/scanner_targets.txt`
- resolves domains to IPv4 addresses
- probes ports (default: `443,2053,2083,2087,2096,8443`)
- stores full reports in:
  - `/var/log/sni-spoofing/scanner/sni-scan-*.json`
  - `/var/log/sni-spoofing/scanner/sni-scan-*.txt`
- prints a summary at the end
- can apply the best candidate directly to `config.json`:
  - `CONNECT_IP`
  - `CONNECT_PORT`
  - `FAKE_SNI` (when best target is a domain)

Run directly:
```bash
sudo python3 /opt/sni-spoofing/deploy/sni_target_scanner.py \
  --config /opt/sni-spoofing/config.json \
  --targets-file /opt/sni-spoofing/deploy/scanner_targets.txt \
  --output-dir /var/log/sni-spoofing/scanner \
  --apply-best
```

Or from manager menu:
- Option `24` runs scanner, applies best result, saves report, and shows summary.
- Option `25` edits targets list.
- Option `26` shows latest saved scanner report.

### Option B: Non-interactive Installer
```bash
cd /path/to/SNI-Spoofing-Pro
chmod +x deploy/install-production.sh
sudo ./deploy/install-production.sh
```

## Offline Bundle (No Direct PyPI Access)
If your target servers cannot reach `pypi.org`, build an offline bundle on an internet-connected Linux server, then transfer it.

### Step 1 (Online Server): Build bundle
```bash
cd /path/to/SNI-Spoofing-Pro
chmod +x deploy/build-offline-bundle.sh
./deploy/build-offline-bundle.sh
```

What this does:
- builds wheels into `deploy/offline-wheels`
- creates bundle tarball like:
  - `../sni-spoofing-offline-bundle-YYYYmmdd-HHMMSS.tar.gz`

### Step 2 (Transfer)
Copy the generated tarball to your offline/limited server.

### Step 3 (Offline Server): Install
```bash
tar -xzf sni-spoofing-offline-bundle-*.tar.gz
cd SNI-Spoofing-Pro
chmod +x deploy/install-production.sh
sudo ./deploy/install-production.sh
```

`install-production.sh` and `sni-manager.sh` now auto-detect local wheelhouse:
- `/opt/sni-spoofing/deploy/offline-wheels`
and install Python deps from there (`--no-index --find-links`) without contacting PyPI.

## Healthcheck
```bash
sudo python3 /opt/sni-spoofing/deploy/healthcheck.py \
  --config /opt/sni-spoofing/config.json \
  --systemd-unit sni-spoofing.service
```

Healthcheck behavior:
- Validates config file existence and parseability
- Validates configured listen port range
- Optionally validates systemd unit is active
- Validates TCP connect to configured local listener

## Manual NFQUEUE Rule Template
If you want to manage rules manually (example queue `1`):
```bash
sudo iptables -I OUTPUT 1 -p tcp -s <LOCAL_IP> -d <CONNECT_IP> --dport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST SYN -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -I OUTPUT 1 -p tcp -s <LOCAL_IP> -d <CONNECT_IP> --dport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST,PSH ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -I INPUT 1 -p tcp -s <CONNECT_IP> -d <LOCAL_IP> --sport <CONNECT_PORT> --tcp-flags SYN,ACK SYN,ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -I INPUT 1 -p tcp -s <CONNECT_IP> -d <LOCAL_IP> --sport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST,PSH ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
```

Delete template:
```bash
sudo iptables -D OUTPUT -p tcp -s <LOCAL_IP> -d <CONNECT_IP> --dport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST SYN -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -D OUTPUT -p tcp -s <LOCAL_IP> -d <CONNECT_IP> --dport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST,PSH ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -D INPUT -p tcp -s <CONNECT_IP> -d <LOCAL_IP> --sport <CONNECT_PORT> --tcp-flags SYN,ACK SYN,ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -D INPUT -p tcp -s <CONNECT_IP> -d <LOCAL_IP> --sport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST,PSH ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
```

Note:
- With `NFQUEUE_FAIL_OPEN=false`, omit `--queue-bypass` in manual rules.
- The application can auto-install and auto-clean tagged rules on Linux.

## Useful Commands
```bash
sudo systemctl restart sni-spoofing
sudo systemctl status sni-spoofing --no-pager
sudo journalctl -u sni-spoofing -f
```
