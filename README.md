### Help
---

```
Using ICMP. Check used/unused ip addresses. If your system block ICMP packet, "scanip" cannot work well

Usage:
  scanip [flags]

Examples:
scanip -c 192.168.0.0/24

Flags:
  -a, --all           Print all addresses (default true)
  -c, --cidr string   Network CIDR (required)
  -h, --help          help for scanip
  -x, --unused        Print unused addresses
  -o, --used          Print used addresses
```

### All list of Address usgae state
---

```
$ sudo scanip -c 172.16.20.0/24

IP_Address              Used
=================================
172.16.20.0             X
172.16.20.1             O
172.16.20.2             O
172.16.20.3             X
172.16.20.4             O
172.16.20.5             X
172.16.20.6             X
172.16.20.7             X
172.16.20.8             X
172.16.20.9             X
172.16.20.10            O
172.16.20.11            X
(...)
```

### Get only used/unused addresses
---

used

```
sudo scanip -c 172.16.20.0/24 -o
IP_Address              Used
=================================
172.16.20.1             O
172.16.20.2             O
172.16.20.4             O
172.16.20.10            O
172.16.20.15            O
172.16.20.16            O
(...)
```

unused

```
sudo scanip -c 172.16.20.0/24 -x
IP_Address              Used
=================================
172.16.20.0             X
172.16.20.3             X
172.16.20.5             X
(...)
```
