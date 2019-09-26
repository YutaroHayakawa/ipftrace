# ipftrace
ipftrace is a tool which tracks the functions that the packets have gone through inside the Linux kernel's L3 layer.
It helps you with understanding how packets are routed inside the kernel.

## Dependencies
- Python3.6 or above
- [BCC](https://github.com/iovisor/bcc)

## Examples

List functions can be tracked
```
$ sudo python3.7 ipftrace.py -l

Available events
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


We can filter the packets by IP address, port number, protocol number and so on.
```
$ ping 8.8.8.8

$ sudo python3.7 ipftrace.py -l3 IPv4 -l4 ICMP
Trace ready!
ICMP		10.0.2.15	->	8.8.8.8	['ip_output']
ICMP		8.8.8.8	->	10.0.2.15	['ip_rcv', 'ip_route_input_noref', 'ip_local_deliver']
...
```

We can trace the packets with lwtunnel excapsulation
```
$ ping 10.0.1.10

$ sudo python3.7 ipftrace.py -s4 10.0.0.10 -s6 fc00::10
Trace ready!
ICMP		10.0.0.10	->	10.0.1.10	['lwtunnel_output', 'seg6_output']
IPv4		fc00::10	->	fc00::11	['ip6_output']
...
```

We can exclude the groups of tracing functions
```
$ ping 10.0.1.10

$ sudo python3.7 ipftrace.py -s4 10.0.0.10 -s6 fc00::10 -e lwt
Trace ready!
ICMP		10.0.0.10	->	10.0.1.10	['seg6_output']
IPv4		fc00::10	->	fc00::11	['ip6_output']
```

## How it works
It's very simple. It just set the kprobe probes and manipurates the `struct sk_buff` inside the probes.
The functions are enumerated in the `events.json`

Here we have some contents in the events.json

```
{
  "events": {
    "ipv4": [
      {
          "name": "ip_local_deliver",
          "args": [
              "struct sk_buff *skb"
          ]
      },
      {
          "name": "ip_rcv",
          "args": [
              "struct sk_buff *skb"
          ]
      },
      ...
      {
          "name": "ipv6_rcv",
          "args": [
              "struct sk_buff *skb"
          ]
      },
      {
          "name": "ip6_input",
          "args": [
              "struct sk_buff *skb"
          ]
      },
      ...
    ],
    "lwt": [
      {
          "name": "lwtunnel_input",
          "args": [
              "struct sk_buff *skb"
          ]
      },
      ...
    ],
    "seg6": [
      {
          "name": "seg6_input",
          "args": [
              "struct sk_buff *skb"
          ]
      },
      ...
    ]
  }
}
```

As you can see, it just enumerate the name of the functions and their argument types.
Adding new functions is very straight forward. The only requirement is that the function
takes `struct sk_buff` as argument.
