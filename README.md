# ipftrace
ipftrace is a tool which tracks the functions that the packets have gone through inside the Linux kernel's L3 layer.
It helps you with understanding how packets are routed inside the kernel.

## Dependencies
- Python3.7
- [BCC](https://github.com/iovisor/bcc)

## Usage

```
Usage: ipftrace.py [OPTIONS] MANIFEST_FILE

  Track the journey of the packets in Linux L3 layer

Options:
  -iv, --ipversion [any|4|6]  Specify IP version
  -l4, --l4proto TEXT         Specify L4 protocol
  -s4, --saddr4 TEXT          Specify IPv4 source address
  -d4, --daddr4 TEXT          Specify IPv4 destination address
  -s6, --saddr6 TEXT          Specify IPv6 source address
  -d6, --daddr6 TEXT          Specify IPv6 destination address
  -sp, --sport TEXT           Specify source port number
  -dp, --dport TEXT           Specify destination port number
  -l, --list                  List available groups and functions
  --help                      Show this message and exit.
```

## Examples

Trace the ICMP packets with source IPv4 address 10.0.1.10
```
$ sudo python ipftrace.py -iv 4 -l4 ICMP -s4 10.0.1.10
```

List functions can be tracked
```
$ sudo python ipftrace.py -l
ipv4
  ip_local_deliver
  ip_rcv
  ip_local_out
  ip_output
  ip_forward
  ip_route_input_noref
vrf
  vrf_l3_rcv
  vrf_l3_out
  vrf_output
  vrf_xmit
  vrf_local_xmit
ipv6
  ipv6_rcv
  ip6_input
...
```

It can trace the packets with lwtunnel excapsulation
```
$ ping 10.0.1.10

$ sudo python ipftrace.py -s4 10.0.0.10 -s6 fc00::10
Trace ready!
ICMP		10.0.0.10	->	10.0.1.10	['lwtunnel_output', 'seg6_output']
IPv4		fc00::10	->	fc00::11	['ip6_output']
...
```

It can exclude the groups of tracing functions
```
$ ping 10.0.1.10

$ sudo python ipftrace.py -s4 10.0.0.10 -s6 fc00::10 -e lwt
Trace ready!
ICMP		10.0.0.10	->	10.0.1.10	['seg6_output']
IPv4		fc00::10	->	fc00::11	['ip6_output']
```

## Manifest file

You need to write the manifest YAML file to specify the functions to trace.
Since the functions and argument types are changed depends on the kernel version,
you may need to write it for each kernel version. But there are some useful enumeration
of the rarely changed functions in the `examples` directory.
```
functions:
  ipv4:                     # Name of the group
  - name: ip_local_deliver  # Name of the function
    args:                   # Types of the arguments it must contain struct sk_buff
    - struct sk_buff *skb

  - name: ip_rcv
    args:
    - struct sk_buff *skb

  - name: ip_local_out
    args:
    - struct net *net
    - struct sock *sk
    - struct sk_buff *skb

  - name: ip_output
    args:
    - struct net *net
    - struct sock *sk
    - struct sk_buff *skb
```
