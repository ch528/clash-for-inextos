# Backend API

The Go server serves the built Vue interface and proxies all Mihomo Controller
requests from the backend. The Controller key and raw configuration are never
returned to the browser. State changes require a matching same-origin request.

## Authentication

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/api/auth/status` | Reports whether the single administrator exists and whether public setup is currently allowed. |
| POST | `/api/auth/setup` | Creates the administrator once. LAN setup needs no token. Public reverse-proxy setup requires a root-authorized 10-minute window. |
| POST | `/api/auth/login` | Username and password login; failures use a uniform message and successful sessions last 12 hours. |
| GET | `/api/auth/me` | Returns the authenticated administrator username. |
| POST | `/api/auth/account` | Changes the username and/or password after checking the current password. |
| POST | `/api/auth/logout` | Invalidates the session. |

## Mihomo and diagnostics

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/api/mihomo/status` | Process state, Controller health, version, PID, and uptime. |
| GET | `/api/mihomo/config` | Mode, selected ports, Controller status, LAN/TUN flags; no secret or raw config. |
| POST | `/api/mihomo/start`, `stop`, `restart` | Controls only the managed Mihomo process. |
| GET | `/api/mihomo/traffic` | Current connection counters and Mihomo total byte counters. |
| GET | `/api/mihomo/connections` | Active connections from the Controller. |
| DELETE | `/api/mihomo/connections` | Closes all active connections. |
| DELETE | `/api/mihomo/connections/{id}` | Closes one connection. |
| GET | `/api/mihomo/proxies`, `groups` | Controller proxy and selectable group data. |
| POST | `/api/mihomo/proxies/{group}` | Selects a member after checking that it belongs to the group. |
| GET | `/api/mihomo/delay/{proxy}` | Tests one proxy; at most five tests run concurrently. |
| GET/POST | `/api/mihomo/mode` | Reads or changes `rule`, `global`, or `direct`. |
| GET | `/api/logs?n=200\|500\|1000` | Bounded tail of backend logs, reading at most 1 MiB. |
| GET | `/api/logs/mihomo` | Bounded tail of Mihomo logs. |
| GET | `/api/diagnostics` | Checks Backend, Mihomo/Controller, Zashboard files, configured ports, subscription counts, :8844 certificate status, saved TUN state, helper availability, and explicitly reports DNS/transparent proxy as not configured. |
| GET | `/api/events?limit=25\|50\|100\|200` | Authenticated system-event history, newest first; event text is fixed and the store retains at most 200 entries. |
| GET | `/api/support` | Downloads a ZIP with system/diagnostic summary, fixed system events, and allowlisted Backend log messages. Omits log attributes, subscription records/URLs, raw Mihomo config, credentials, cookies, and private keys. |
| GET | `/api/remote-access` | Reports the public IPv6 on `ppp0` or the IPv6 default-route interface and checks the certificate actually served on local `[::1]:8844` for that IP SAN and validity. |

## Update checks

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/api/updates/check` | Checks stable release metadata for Clash for iNextOS, Mihomo, Zashboard, and Geo data. Requires administrator authentication; never downloads or installs artifacts. |
| GET | `/api/updates/app/status` | Returns root-managed application update status through the fixed privileged helper. |
| POST | `/api/updates/app` | Starts the fixed systemd updater. It validates the ARM64 Debian package and release digest, keeps the current release package for rollback, preserves the saved `app.yaml`, and installs the new package. Network capture must be off. |
| POST | `/api/updates/mihomo` | Downloads and validates the fixed official ARM64 release through the privileged helper, stops the managed process, installs atomically, checks startup health, and restores the old binary on startup failure. Requires administrator authentication and same-origin mutation checks. |
| POST | `/api/updates/zashboard` | Downloads the official `dist.zip`, verifies size and SHA-256, extracts into a private candidate directory, validates entry resources/notices, and activates through an atomic version record. |
| POST | `/api/updates/zashboard/rollback` | Validates and reactivates the retained previous panel while preserving the version being replaced. |

## Network settings

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/api/network/status` | Returns saved TUN options, capture/rollback status, helper capability, LAN clients, proxy scope, and DNS preferences. |
| POST | `/api/network/settings` | Saves TUN stack, MTU, IPv4/IPv6 routes, Auto Route, Auto Redirect, Strict Route, LAN proxy, bypass and DNS preferences. Active capture must be turned off before changing settings. |
| POST | `/api/network/confirm`, `/api/network/restore` | Confirms a successful protected capture test or disables application-owned capture and invokes recovery. |

The check uses fixed GitHub API endpoints and public-address validation for
requests and redirects. It reports installed and latest versions and release
dates where comparison is supported. The Clash for iNextOS release source is
`ch528/clash-for-inextos`; the package updater checks the stable release tag and
exact ARM64 asset (`inextos-clash_1.0.0_arm64.deb` for the formal release,
`inextos-clash_1.0.0-N_arm64.deb` for a development revision). Downloads try GitHub release
mirrors before the direct asset URL, and every route must match the SHA-256
digest returned by the GitHub release API. Geo usage is detected from active
rules and local data files so unused datasets are not presented as installed.
Mihomo updates preserve the original desired running state and serialize with
lifecycle operations, the supervisor, subscription refreshes and API mutations.
Recovery uses a separate bounded context if the original request is cancelled.
Responses report `updated`, `rolled_back` and `running`; failures return HTTP
503 with `error` and `result`. Helper requests accept only fixed actions, never
caller-selected URLs, paths or executable bytes. The application updater runs
in a separate root-owned systemd unit so replacing/restarting the Backend does
not kill the installer. It uses `DEBIAN_FRONTEND=noninteractive`,
`--force-confold`, and `--force-downgrade` for the exact package already
validated against the release metadata, waits for the expected Debian version and local health
endpoint, and restores the prior package if that check fails. Automatic
rollback is covered by a local test. Live device acceptance first moved the
ARM64 installation from `1.0.0-35` to `1.0.0-36`; the published package digest
matched, installation completed, the local health check returned HTTP 200, and
application settings, administrator state, Controller secret, and subscription
data retained their pre-update SHA-256 hashes. On 2026-10-12, the authenticated
Edge Update page detected and installed public release `1.0.37` (`1.0.0-37`).
Its SHA-256 matched the GitHub Release API digest. The About page showed
`1.0.37`, and a fresh update check reported `1.0.37` as both current and latest.
Mihomo remained running, the saved `主订阅` remained active with 67 nodes, and
network capture remained disabled. The completion banner still showed the
previous text `应用已更新；管理页面正在恢复`; the installed version and latest
release were confirmed independently in About and the Update page. The updater
unit continues running from the pre-update process while replacing the package,
so the completion text should be rechecked after the next update. No router
reboot was performed. Zashboard source implementation
preserves the bundled panel and retains immutable release directories under the
app data directory. Invalid candidates do not change the active version record;
ZIP traversal, duplicate paths, symlinks, special files, excessive extraction
and missing entry resources are rejected. Old hashed asset requests can use the
previous version during a browser transition. Mihomo and Zashboard live
update/rollback acceptance, Zashboard browser acceptance, and Geo installation
remain pending.

## Subscriptions

| Method | Path | Behavior |
| --- | --- | --- |
| GET/POST | `/api/subscriptions` | Lists masked records, update schedules, and quota metadata when supplied by `Subscription-Userinfo`, or stores an SSRF-checked URL. |
| PATCH | `/api/subscriptions/{id}` | Edits the name, enabled state, and auto-update period (off or 1–720 hours; 6/12/24 are presets). |
| POST | `/api/subscriptions/{id}/update` | Downloads, validates inline proxies/groups/rules, runs Mihomo config test, then atomically stores the profile. A failed test or restart keeps the prior working configuration. |
| POST | `/api/subscriptions/{id}/activate` | Tests and switches to a previously downloaded profile. |
| DELETE | `/api/subscriptions/{id}` | Deletes a record and its downloaded copy. |

Imported settings retain the application's loopback Controller, local proxy
port, LAN-disabled, and TUN-disabled boundary. Subscription URLs and content
stay on the device unless the administrator explicitly exports a portable backup.
Subscription records include `last_updated` and `next_update`; failed automatic
updates are retried after 15 minutes without changing the last-known-good profile.

## Portable backup and restore

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/api/backup/export` | Downloads a versioned JSON backup with app/runtime and network proxy preferences, subscriptions and cached profiles. |
| POST | `/api/backup/preview` | Validates the schema, subscription metadata and generated Mihomo configs; makes no changes. |
| POST | `/api/backup/apply` | Revalidates and replaces the application-owned subscription data and runtime preferences. Requires Mihomo stopped. |

The backup includes runtime mode, local proxy ports, TUN stack preference,
startup/recovery preferences, subscription refresh schedules, subscription
URLs and node credentials, plus browser appearance when exported from the UI.
The downloaded file is sensitive. It excludes the administrator password hash,
Controller secret, TLS private key, iNextOS app configuration and runtime logs.
Applying a backup preserves the local Controller secret, keeps Mihomo stopped,
and forces TUN off. The restore replaces the app's subscription list; it does
not alter the account or public HTTPS configuration.

## Process ownership

At startup, the manager checks a saved PID against `/proc/<pid>/cmdline`; if
the PID is stale, it scans for the exact Mihomo executable/config/runtime
argument tuple. Duplicate starts are idempotent, and port collisions are
reported without changing firewall or routing state.
