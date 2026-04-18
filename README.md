# SNI-Spoofing
Bypass DPI with IP/TCP header manipulation.

## Platform Model
- Windows: WinDivert (`pydivert`) path
- Linux (Ubuntu): Active interception with `NFQUEUE` (not passive sniff-only)

## Linux Requirements
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-dev build-essential libpcap-dev libnetfilter-queue-dev iptables
pip3 install -r requirements.txt
```

## Config
`config.json` keys:
- `LISTEN_HOST`
- `LISTEN_PORT`
- `CONNECT_IP`
- `CONNECT_PORT`
- `FAKE_SNI`
- `NFQUEUE_NUM` (optional, default: `1`)
- `NFQUEUE_MAXLEN` (optional, default: `4096`)
- `NFQUEUE_FAIL_OPEN` (optional, default: `true`)
- `NARROW_NFQUEUE_FILTER` (optional, default: `true`)
- `BYPASS_TIMEOUT`
- `CONNECT_TIMEOUT`
- `FAKE_DELAY_MS`
- `BROWSER_PROFILE` (`legacy` / `random` / `chrome` / `firefox` / `safari` / `edge`)
- `TTL_SPOOF`
- `FAKE_SEND_WORKERS`
- `RECV_BUFFER`
- `MAX_CONNECTIONS`
- `IDLE_TIMEOUT`
- `RATE_LIMIT`
- `HANDLE_LIMIT`
- `ACCEPT_BACKLOG`
- `RESOURCE_PRESSURE_BACKOFF`
- `LOG_LEVEL`
- `LOG_FILE`
- `LOG_CLIENT_SNI`
- `STATS_INTERVAL`

## Run On Ubuntu
```bash
cd /path/to/SNI
sudo python3 main.py
```

The Linux injector now:
1. Intercepts handshake packets via `NFQUEUE`.
2. Holds the outbound ACK packet in queue.
3. Sends fake TLS packet with `wrong_seq`.
4. Calls `packet.accept()` so the original ACK exits immediately after fake packet.

Runtime features:
- Structured logging (`LOG_LEVEL`, optional `LOG_FILE`)
- Connection rate limiting per source IP (`RATE_LIMIT`)
- Concurrent connection limit (`MAX_CONNECTIONS`)
- Relay idle timeout (`IDLE_TIMEOUT`)
- Accept-loop concurrency guard (`HANDLE_LIMIT`)
- Periodic stats with top SNI visibility (`STATS_INTERVAL`)
- Browser-like TLS fingerprint generation (`BROWSER_PROFILE`)
- Humanized fake-send timing and optional TTL spoof (`FAKE_DELAY_MS`, `TTL_SPOOF`)
- Worker-queue fake packet sender (`FAKE_SEND_WORKERS`)
- NFQUEUE queue hardening with maxlen + retry loop (`NFQUEUE_MAXLEN`)
- Fail-open/fail-closed behavior control (`NFQUEUE_FAIL_OPEN`)
- Narrow or wide NFQUEUE rule mode (`NARROW_NFQUEUE_FILTER`)

## Exact iptables Commands (Manual Mode)
If you want to manage rules manually (example `NFQUEUE_NUM=1`):
```bash
sudo iptables -I OUTPUT 1 -p tcp -s <LOCAL_IP> -d <CONNECT_IP> --dport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST SYN -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -I OUTPUT 1 -p tcp -s <LOCAL_IP> -d <CONNECT_IP> --dport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST,PSH ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -I INPUT 1 -p tcp -s <CONNECT_IP> -d <LOCAL_IP> --sport <CONNECT_PORT> --tcp-flags SYN,ACK SYN,ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -I INPUT 1 -p tcp -s <CONNECT_IP> -d <LOCAL_IP> --sport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST,PSH ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
```

Delete rules:
```bash
sudo iptables -D OUTPUT -p tcp -s <LOCAL_IP> -d <CONNECT_IP> --dport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST SYN -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -D OUTPUT -p tcp -s <LOCAL_IP> -d <CONNECT_IP> --dport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST,PSH ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -D INPUT -p tcp -s <CONNECT_IP> -d <LOCAL_IP> --sport <CONNECT_PORT> --tcp-flags SYN,ACK SYN,ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
sudo iptables -D INPUT -p tcp -s <CONNECT_IP> -d <LOCAL_IP> --sport <CONNECT_PORT> --tcp-flags SYN,ACK,FIN,RST,PSH ACK -m comment --comment sni-spoof-nfq-1 -j NFQUEUE --queue-num 1 --queue-bypass
```

## Notes
- Run as root (`sudo`) because `NFQUEUE` and raw packet send require privileged access.
- Rules are also installed/cleaned up automatically by the Linux injector path.

## Production Rollout (systemd)
Deployment assets are under `deploy/`:
- `deploy/sni-spoofing.service.template`
- `deploy/install-production.sh`
- `deploy/healthcheck.py`
- `deploy/logrotate-sni-spoofing.conf`

Recommended install:
```bash
cd /path/to/SNI
chmod +x deploy/install-production.sh
sudo ./deploy/install-production.sh
```

Unified manager (recommended):
```bash
cd /path/to/SNI
chmod +x deploy/sni-manager.sh
sudo ./deploy/sni-manager.sh
```

Behavior:
- First run: installs packages/dependencies, deploys to `/opt/sni-spoofing`, installs systemd/logrotate, starts service, then opens menu.
- Next runs: directly opens the interactive menu.

Manager menu includes:
- start/stop/restart/reset pipeline
- service status
- journal logs (live/recent)
- app file logs (if `LOG_FILE` is set)
- healthcheck + config validation
- quick config wizard + manual config edit
- NFQUEUE tuning profile + NFQUEUE iptables inspection/cleanup
- config backup/restore
- force logrotate
- upgrade/reinstall + uninstall

Healthcheck example:
```bash
sudo python3 /opt/sni-spoofing/deploy/healthcheck.py --config /opt/sni-spoofing/config.json --systemd-unit sni-spoofing.service
```

Useful systemd commands:
```bash
sudo systemctl restart sni-spoofing
sudo systemctl status sni-spoofing --no-pager
sudo journalctl -u sni-spoofing -f
```
