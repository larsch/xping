# mping

Command line ping re-imagined. Sends ICMP echo requests and measures round-trip
time to target host, with bells and whistles.

## Usage

<!-- BEGIN CLI -->
```
Command line ping, re-imagined.

Usage: mping [OPTIONS] <TARGET>

Arguments:
  <TARGET>  Address or name of target host

Options:
  -r, --rate <RATE>          Number of packets per second
  -i, --interval <INTERVAL>  Packet interval in milliseconds [default: 1000]
  -c, --count <COUNT>        Number of attempts (default infinite)
  -w, --timeout <TIMEOUT>    Timeout waiting for response in milliseconds [default: 1000]
  -l, --length <LENGTH>      Length of ICMP payload in bytes [default: 64]
  -d, --display <DISPLAY>    Display mode [default: classic] [possible values: classic, char, dumb, char-graph, debug, none]
  -t, --ttl <TTL>            Time to live [default: 64]
  -a, --api <API>            API to use [default: icmp-socket] [possible values: icmp-socket, iphelper]
  -4, --ipv4                 Force using IPv4
  -6, --ipv6                 Force using IPv6
      --update-readme
  -h, --help                 Print help (see more with '--help')
  -V, --version              Print version

```
<!-- END CLI -->


## Differences to classic ping

- Continues sends echo requests without blocking while waiting for responses or timeout
- Allows sending at very high packet rates (thousands of packets per second, use with caution)
- Displays sent packets and updates display of received packets asynchronously
- Multiple display modes (`--display` option):
    - Classic mode (default): similar to classic ping (but with async update)
    - Char mode: displays a character for each probe, updated on reception or timeout
    - Debug: displays all internal data
- No need for root/administrator privileges

## Features

- IPv4 and IPv6 support
- Configurable packet rate, length, & TTL
- Supports Windows and Linux, with multiple APIs (`--api=...`):
    - Windows: IP Helper API (`iphelper`, default) and raw ICMP sockets (`icmp-socket`)
    - Linux: ICMP sockets (`icmp-socket`)
- IP_RECVERR support on Linux (for detailed error messages)

## Missing features & ideas

- OS timestamping (SO_TIMESTAMP)
- Packet loss statistics
- Packet loss graph
- Support more than 64 outstanding packets on Windows (currently limited by WaitForMultipleObjects)
- Show latency statistics (min, max, avg)
- Show receive TTL
