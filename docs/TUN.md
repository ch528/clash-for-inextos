# TUN

TUN, LAN proxy, and LAN DNS takeover are off by default. Supported stacks are `system`, `gvisor`, and `mixed`; the package validates the generated configuration with the installed Mihomo binary before applying it. Defaults are device `mihomo0`, IPv4 and IPv6 routing on, MTU 1500, Auto Route on, Auto Redirect off, and Strict Route off. IPv4/IPv6 selections become explicit Mihomo `route-address` CIDRs. With IPv6 Auto Route, Mihomo's policy-rule index starts at 8700 so its TUN route runs before iNextOS's existing priority-8800 main-table rule, while earlier system-specific rules keep precedence. MTU accepts 576–9000, with IPv6 requiring at least 1280. Auto Redirect and Strict Route require Auto Route; LAN proxy and DNS takeover also require Auto Route. Existing runtime state migrates to both route families enabled because earlier builds routed both when TUN was enabled. TUN-only mode starts Mihomo's loopback DNS and hijacks the router's own port-53 requests so router-originated hostname lookups keep working. It leaves Auto Redirect off, so this does not capture LAN clients. The separate DNS takeover option controls DNS forwarding for LAN clients.

The Backend has no network administration capability. It asks the root helper to start the separate Mihomo systemd unit. Only that unit receives `CAP_NET_ADMIN` and access to `/dev/net/tun`.

Before the first capture test on a device, save one complete baseline of addresses, IPv4/IPv6 routes and policy rules, nftables, resolver state, and listening sockets. The enable operation also saves the previous generated Mihomo config/runtime state and arms a four-minute systemd rollback timer before changing the active config. Confirm only after SSH, the management page, DNS, IPv4/IPv6, and Internet access have been checked. If not confirmed, the timer restores the previous config, disables TUN/LAN/DNS capture, and restarts the Backend.

Manual confirmation:

```sh
sudo inextos-clash network-confirm
```

The Network page can also confirm the test. To disable capture, turn it off in the page or run the network recovery action. Do not reboot during the first test.

