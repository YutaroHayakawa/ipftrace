# ipftrace

Now we have more sophisticated (and compact) implementation in [ipftrace2](https://github.com/YutaroHayakawa/ipftrace2)
repository. Please check it as well.

## TL;DR
ipftrace is a simple function tracer for Linux networking code with flow based filtering. It is similar to the ftrace in some sense but, you can trace **which flow have gone through which functions** inside the kernel which is usually more important information for the network people than **which functions are called** information provided by ftrace.

## Usage

```
Usage: ipftrace [OPTIONS] MANIFEST

  Track the journey of the packets in Linux network stack

Options:
  -iv, --ipversion [4|6]  Specify IP version
  -s, --saddr TEXT        Specify IP source address
  -d, --daddr TEXT        Specify IP destination address
  -p, --proto TEXT        Specify protocol
  -sp, --sport TEXT       Specify source port number
  -dp, --dport TEXT       Specify destination port number
  -m, --module TEXT       Specify custom match module name
  -r, --regex TEXT        Filter the function names by regex
  -l, --length INTEGER    Specify the length of function trace
  -ls, --list-func        List available functions
  --help                  Show this message and exit.
```

## Install

### Dependencies
- Python3.7 or above
- [BCC](https://github.com/iovisor/bcc)

### Docker

```
$ git clone https://github.com/YutaroHayakawa/ipftrace
$ cd ipftrace
$ sudo ./scripts/ipftrace-docker -p ICMP examples/manifest/generic.yaml
```

ipftrace-docker is a wrapper script for `docker run`. Since the ipftrace container requires some boring things to make it work (like expose the Linux source to the container, make container privileged, uploading manifest file to the container and so on), this script does it for you.

### On your system

```
$ git clone https://github.com/YutaroHayakawa/ipftrace
$ cd ipftrace
$ sudo pip3 install .
$ sudo ipftrace -p ICMP examples/manifest/generic.yaml
```

## Examples

Trace the ping ICMP packets
```
# ipftrace -p ICMP examples/manifest/5.4.0-rc7-btf.yaml
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
# ipftrace -p TCP -d 10.231.206.32 -dp 8000 -m examples/module/gso.py examples/5.4.0-rc7-btf.yaml
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

## Manifest file
ipftrace needs the YAML file called **manifest file**. Which seems like below.

```YAML
functions:
  - name: ip_rcv
    skb_pos: 1

  - name: ip_local_out
    skb_pos: 3

  - name: ip_output
    skb_pos: 3

  - name: ip_local_deliver_finish
    skb_pos: 3
    egress: true

  - name: ip_forward
    skb_pos: 1

  - name: ip_route_input_noref
    skb_pos: 1

<...>
```

It contains following informtations.

- `name` : The symbol name of the function to trace
- `skb_pos` : The position of the struct sk_buff* in the function arguments
- `egress` : (optional) Indicates the end of the function chain

As for the `name`, you can specify any kernel functions which takes struct sk_buff* as an argument (the symbol must be exported). In addition to the function name, we need `skb_pos` which indicates the position of the struct sk_buff* in the argument list of the function (the first argument is position 1).

`egress` indicates the end of the function tracing. The list of the functions for the flow will be terminated and displayed when the packet reaches to the function annotated with `egress: true`. You need to find appropriate egress function to get correct result from ipftrace. This is probably a most difficult part of the ipftrace.

As for today, you need to write the manifest file by your self. But the grows of the BTF (BPF Type Format) infrastructure will greatly reduce the time to write it (but you still need to find the egress function). Currently we have an example manifest in the `examples`. Feel free to use it.

We also have useful experimental script to generate the manifest from BTF information in vmlinux. Please checkout `scripts/btf_to_manifest.py`. 

## How it works?
It uses eBPF + kprobe for attaching the tracing programs to the kernel, parse the packet in the kprobe, filter out the unneccesary packets and output some log through perf. That's it. 

## Limitations and Tips
- ipftrace cannot trace the function with skb_pos > 4 due to the limitation of the eBPF.
- We recommend you to mark `kfree_skb` with `egress: true` this will catch the case which netfilter drops the packet.
- ipftrace depends on the skb->network_header and skb->protocol to determine the IP address of the packet. So, if these informations are invalid, it cannot trace the function correctly. Due to this, ipftrace usually cannot trace the functions belongs to the "higher" layer than IP for TX path and "lower" layer than IP for RX path.
