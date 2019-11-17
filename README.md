# What is this and what is this for?
ipftrace is a tool which tracks the functions that the packets have gone through inside the Linux kernel. It is inspired by ftrace, but the primary difference between ftrace is that it supports the flow based trace filtering. Function tracing which is not aware of the flow is usually useless for observing the behavior of the networking code because we usually want to know which flow have gone through the functions.

## Dependencies
- Python3.7 or above
- [BCC](https://github.com/iovisor/bcc)

## Usage

```
Usage: ipftrace [OPTIONS] MANIFEST_FILE

  Function tracer for Linux networking code with flow based filtering

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
  -l, --list                  List available functions
  --help                      Show this message and exit.
```

## Examples

Trace the ICMP packets with source IPv4 address 10.0.1.10
```
# ipftrace -l4 ICMP examples/5.4.0-rc7-btf.yaml
<...>
ICMP	10.231.244.75	->	10.128.218.64
     Time Stamp  Function
495406078818070  nf_hook_slow
495406078929728  ip_output
495406078949359  nf_hook_slow
495406078970951  dev_queue_xmit
495406078986098  netdev_core_pick_tx
495406079008937  sch_direct_xmit
495406079024885  validate_xmit_skb_list
495406079036226  netif_skb_features
495406079057803  passthru_features_check
495406079071811  skb_network_protocol
495406079091507  dev_queue_xmit_nit
495406079106655  skb_clone
495406079132195  consume_skb
495406079143957  skb_release_head_state
495406079157152  skb_clone_tx_timestamp
495406079179885  skb_to_sgvec

ICMP	10.128.218.64	->	10.231.244.75
     Time Stamp  Function
495406113277061  skb_copy_datagram_iter
495406113320933  __sock_recv_ts_and_drops
495406113354230  __sock_recv_timestamp
495406113373470  skb_free_datagram
495406113393790  consume_skb
495406113408876  skb_release_head_state
495406113426471  sock_rfree
495406112568847  inet_gro_receive
495406112662367  skb_defer_rx_timestamp
495406112712251  consume_skb
495406112732787  ip_rcv
495406112784692  nf_hook_slow
495406112811560  nf_ip_checksum
495406112837230  __skb_checksum_complete
495406112856814  __skb_checksum
495406112883108  ip_route_input_noref
495406112905093  ip_route_input_rcu
495406112928973  fib_validate_source
495406112952321  ip_local_deliver
495406112972174  nf_hook_slow
495406112999152  ip_protocol_deliver_rcu
495406113020418  raw_local_deliver
495406113047608  skb_clone
495406113074430  raw_rcv
495406113109356  ipv4_pktinfo_prepare
495406113132611  sock_queue_rcv_skb
495406113169237  sk_filter_trim_cap
495406113198364  security_sock_rcv_skb
495406113230150  __sock_queue_rcv_skb
495406113260665  icmp_rcv
495406113289802  ping_rcv
495406113368263  kfree_skb
```

Trace the GSO behavior with custom module
```
# ipftrace -l4 TCP -d4 10.231.206.32 -dp 8000 examples/5.4.0-rc7-btf.yaml
<...>
TCP    10.231.244.75:33696    ->    10.231.206.32:8000
     Time Stamp  Function                      Custom Data
490440712480226  nf_hook_slow                  (len: 2101 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712519497  ip_output                     (len: 2101 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712538213  nf_hook_slow                  (len: 2101 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712549567  skb_gso_validate_network_len  (len: 2101 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712566096  neigh_resolve_output          (len: 2101 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712578933  eth_header                    (len: 2101 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712594839  dev_queue_xmit                (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712604856  netdev_core_pick_tx           (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712614715  sch_direct_xmit               (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712623331  validate_xmit_skb_list        (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712631858  netif_skb_features            (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712641404  passthru_features_check       (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712653638  skb_network_protocol          (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712661015  __skb_gso_segment             (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712673966  skb_mac_gso_segment           (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712683431  skb_network_protocol          (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712688616  inet_gso_segment              (len: 2101 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712705180  tcp_gso_segment               (len: 2081 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712717131  skb_network_protocol          (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712750240  consume_skb                   (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712759857  skb_release_head_state        (len: 2115 gso_size: 1448 gso_segs: 2 gso_type: SKB_GSO_TCPV4)
490440712772181  dev_queue_xmit_nit            (len: 1514 gso_size: 0 gso_segs: 0 gso_type: )
```
