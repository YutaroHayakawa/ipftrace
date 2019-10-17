#include <net/dst.h>
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/ptrace.h>

#define member_read(_dst, _src, _member)                 \
  do{                                                    \
    bpf_probe_read(                                      \
      _dst,                                              \
      sizeof(_src->_member),                             \
      ((char*)_src) + offsetof(typeof(*_src), _member)   \
    );                                                   \
  } while(0)

struct event_data {
  uint8_t event_id;
  uint8_t l4_protocol;
  uint16_t l3_protocol;
  union {
    struct {
      uint32_t saddr;
      uint32_t daddr;
    } v4;
    struct {
      uint8_t saddr[16];
      uint8_t daddr[16];
    } v6;
  };
  uint16_t sport;
  uint16_t dport;
  uint8_t data[64];
};

static inline bool
ipv4_match(uint8_t **head, struct event_data *e)
{
  bool ret = true;
  struct iphdr iph;

  bpf_probe_read(&iph, sizeof(iph), *head);

  e->v4.saddr = iph.saddr;
#ifndef SADDRV4_ANY
  if (e->v4.saddr != SADDRV4) ret = false;
#endif

  e->v4.daddr = iph.daddr;
#ifndef DADDRV4_ANY
  if (e->v4.daddr != DADDRV4) ret = false;
#endif

  /*
   * Skip the options
   */
  *head = *head + (iph.ihl * 4);

  e->l4_protocol = iph.protocol;

  return ret;
}

static inline bool
ipv6_match(uint8_t **head, struct event_data *e)
{
  struct ipv6hdr iph;

  bpf_probe_read(&iph, sizeof(iph), *head);

  memcpy(e->v6.saddr, &iph.saddr, 16);
#ifndef SADDRV6_ANY
  uint8_t saddr[16] = { SADDRV6 };
  #pragma unroll
  for (int i = 0; i < 16; i++)
    if (e->v6.saddr[i] != saddr[i]) return false;
#endif

  memcpy(e->v6.daddr, &iph.daddr, 16);
#ifndef DADDRV6_ANY
  uint8_t daddr[16] = { DADDRV6 };
  #pragma unroll
  for (int i = 0; i < 16; i++)
    if (e->v6.daddr[i] != daddr[i]) return false;
#endif

  /*
   * Skip the extension headers.
   * Due to the limitation of the BPF we only can handle
   * limited number of headers (we chose 8 in here for now).
   */
  uint8_t nexthdr = iph.nexthdr;
  uint8_t nexthdr_len = sizeof(iph);

  #pragma unroll
  for (int i = 0; i < 8; i++) {
    if (nexthdr == 0 || nexthdr == 41 ||
        nexthdr == 43 || nexthdr == 44) {
      *head += nexthdr_len;
      bpf_probe_read(&nexthdr, 1, *head);
      bpf_probe_read(&nexthdr_len, 1, *head + 1);
    } else {
      break;
    }
  }

  e->l4_protocol = nexthdr;

  return true;
}

static inline bool
tcp_match(uint8_t **head, struct event_data *e)
{
  struct tcphdr tcph;

  bpf_probe_read(&tcph, sizeof(tcph), *head);

  e->sport = tcph.source;
#ifndef SPORT_ANY
  if (e->sport != SPORT) return false;
#endif

  e->dport = tcph.dest;
#ifndef DPORT_ANY
  if (e->dport != DPORT) return false;
#endif

  return true;
}

static inline bool
udp_match(uint8_t **head, struct event_data *e)
{
  struct udphdr udph;

  bpf_probe_read(&udph, sizeof(udph), *head);

  e->sport = udph.source;
#ifndef SPORT_ANY
  if (e->sport != SPORT) return false;
#endif

  e->dport = udph.dest;
#ifndef DPORT_ANY
  if (e->dport != DPORT) return false;
#endif

  return true;
}

static inline bool
match(struct pt_regs *ctx, struct sk_buff *skb, struct event_data *e)
{
  bool matched;
  uint8_t *head;
  uint16_t ipofs;

  member_read(&head, skb, head);
  member_read(&ipofs, skb, network_header);
  member_read(&e->l3_protocol, skb, protocol);

  head += ipofs;

#ifndef L3_PROTOCOL_ANY
  if (e->l3_protocol != L3_PROTOCOL) return false;
#endif

  switch (e->l3_protocol) {
    case 0x0008: /* IPv4 */
      matched = ipv4_match(&head, e);
      break;
    case 0xdd86: /* IPv6 */
      matched = ipv6_match(&head, e);
      break;
    default:
      matched = false;
      break;
  }

  if (!matched) return false;

#ifndef L4_PROTOCOL_ANY
  if (e->l4_protocol != L4_PROTOCOL) return false;
#endif

  /* 
   * We will match to the inner most header for tunneling protocols
   * so, ignore the L3 protocol `matched` flag for them.
   */
  switch (e->l4_protocol) {
    case 6: /* TCP */
      matched = tcp_match(&head, e);
      break;
    case 13: /* UDP */
      matched = udp_match(&head, e);
      break;
    default:
      break;
  }

  if (!matched) return false;

  return true;
}

/*
 * Default tracing action
 */
BPF_PERF_OUTPUT(events);

static inline void
action(struct pt_regs *ctx, struct event_data *e)
{
  events.perf_submit(ctx, e, sizeof(*e));
}
