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
  -m, --module TEXT           Specify custom match module name
  -l, --list                  List available groups and functions
  --help                      Show this message and exit.
```

## Examples

Trace the ICMP packets with source IPv4 address 10.0.1.10
```
$ sudo python ipftrace.py -iv 4 -l4 ICMP -s4 10.0.1.10
ICMP	10.0.1.10	->	10.0.1.11
      Time Stamp  Function
1980357215835183  ip_output
1980357215867067  ip_finish_output2
1980357215884858  validate_xmit_skb
1980357215887496  dev_hard_start_xmit

ICMP	10.0.1.11	->	10.0.1.10
      Time Stamp  Function
1980357216186467  ip_rcv
1980357216191031  ip_route_input_noref
1980357216193923  ip_local_deliver
1980357216196007  ip_local_deliver_finish
1980357216202247  kfree_skb
```

Trace the GSO behavior with custom module
```
$ sudo python ipftrace.py -iv 4 -l4 TCP -d4 10.0.1.11

...

TCP	10.0.1.10:52262	->	10.0.1.11:31337
      Time Stamp  Function             Custom Data
1980216709532312  ip_output            (len: 2101 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
1980216709556754  ip_finish_output2    (len: 2101 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
1980216709564468  validate_xmit_skb    (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
1980216709567884  __skb_gso_segment    (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
1980216709570449  skb_mac_gso_segment  (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
1980216709573461  inet_gso_segment     (len: 2101 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
1980216709581026  tcp_gso_segment      (len: 2081 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
1980216709591009  dev_hard_start_xmit  (len: 1514 gso_size: 0 gso_segs: 0 gso_type: )
```

List functions can be tracked
```
$ sudo python ipftrace.py -l examples/generic.yaml
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
