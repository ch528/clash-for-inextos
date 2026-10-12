# Security model

- The Web/API service runs as the inextos-clash system user with an empty CapabilityBoundingSet and NoNewPrivileges=true. It may use AF_NETLINK only for read-only interface, route, and neighbor discovery.
- The dedicated Mihomo TUN service alone receives `CAP_NET_ADMIN` and `/dev/net/tun` access. It is not enabled at boot as a separate unit; the Backend starts it only when saved TUN state requests it.
- The root helper accepts a bounded JSON object containing a single fixed action. It has no `exec`, shell, arbitrary path, command argument, or generic file API.
- The helper socket is root-owned, group-readable/writable by `inextos-clash`, and placed in a root-owned non-writable runtime directory.
- Controller and Mixed Port are loopback-only. Zashboard requests pass through an authenticated same-origin reverse proxy. The Browser never receives the Controller secret.
- Public first-run setup requires the ten-minute `setup-open` window. Direct LAN setup is scoped to the actual LAN listener. Creation events record username, scope, and trusted source IP, never the password or hash.
- Administrator passwords use Argon2id. Subscription URLs are masked in the UI; application logs store subscription IDs rather than URLs.
- Rollback stops only the dedicated Mihomo unit and restores files owned by this application. There is no `nft flush`, broad route deletion, sing-box edit, or RoceOS database write.

