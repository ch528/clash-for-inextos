# Recovery

## Automatic TUN recovery

The first unconfirmed TUN enable has a four-minute systemd timer. It restores the saved non-TUN config, stops only `inextos-clash-mihomo.service`, writes the previous runtime state, and restarts `inextos-clash.service`.

## Manual recovery

If the Web UI is reachable, use **网络代理 → 恢复网络**. If it is not reachable, the scheduled rollback runs without an SSH session. After connectivity returns, inspect only the application services:

```sh
sudo systemctl status inextos-clash.service inextos-clash-helper.service inextos-clash-mihomo.service
sudo inextos-clash status
```

To confirm that the first test passed, use `sudo inextos-clash network-confirm`. To request the saved rollback immediately, use `sudo inextos-clash network-rollback`.

`apt remove inextos-clash` stops the application core and helper while retaining configuration and user data. `apt purge inextos-clash` then removes only `/etc/inextos-clash/` and `/var/lib/inextos-clash/` owned by this application. Neither operation flushes firewall tables or edits sing-box, Docker, IPTV, or iNextOS configuration.

