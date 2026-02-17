
# ping-sweep

Full /16 in 0.2s. No root required.

```
nix run github:tupakkatapa/ping-sweep -- --help
```

```
Performs a ping sweep on a given subnet

Usage: ping-sweep [OPTIONS]

Options:
  -s, --subnet <SUBNET>  Subnet in CIDR notation, IPv4 or IPv6 (auto-detected if omitted)
  -t, --timeout <MS>     Ping timeout in milliseconds [default: 200]
  -j, --json             Output results as a JSON array
  -R, --rtt              Show round-trip time for each host
  -r, --resolve          Resolve hostnames via reverse DNS
  -m, --mac              Show MAC addresses from ARP table
  -h, --help             Print help
  -V, --version          Print version
```
