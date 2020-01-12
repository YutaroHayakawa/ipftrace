from ctypes import *
from enum import IntFlag


class FeatureFlags(IntFlag):
    SKB_GSO_TCPV4 = 1 << 0
    SKB_GSO_DODGY = 1 << 1
    SKB_GSO_TCP_ECN = 1 << 2
    SKB_GSO_TCP_FIXEDID = 1 << 3
    SKB_GSO_TCPV6 = 1 << 4
    SKB_GSO_FCOE = 1 << 5
    SKB_GSO_GRE = 1 << 6
    SKB_GSO_GRE_CSUM = 1 << 7
    SKB_GSO_IPXIP4 = 1 << 8
    SKB_GSO_IPXIP6 = 1 << 9
    SKB_GSO_UDP_TUNNEL = 1 << 10
    SKB_GSO_UDP_TUNNEL_CSUM = 1 << 11
    SKB_GSO_PARTIAL = 1 << 12
    SKB_GSO_TUNNEL_REMCSUM = 1 << 13
    SKB_GSO_SCTP = 1 << 14
    SKB_GSO_ESP = 1 << 15
    SKB_GSO_UDP = 1 << 16
    SKB_GSO_UDP_L4 = 1 << 17


class GSOData(Structure):
    _fields_ = [
        ("len", c_uint),
        ("gso_size", c_ushort),
        ("gso_segs", c_ushort),
        ("gso_type", c_uint),
    ]


def parse_features(features):
    ret = []
    for f in FeatureFlags:
        if features & f:
            ret.append(str(f.name))
    return "|".join(ret)


def get_name():
    return "GSO"


def generate_header():
    return """
    struct gso_data {
      unsigned int len;
      unsigned short gso_size;
      unsigned short gso_segs;
      unsigned int gso_type;
    };
    """


def generate_body():
    return """
    static inline bool
    custom_match(void *ctx, struct sk_buff *skb, uint8_t *data) {
      void *head;
      sk_buff_data_t end;
      struct skb_shared_info *shinfo;
      struct gso_data *gd = (struct gso_data *)data;

      member_read(&head, skb, head);
      member_read(&end, skb, end);
      member_read(&gd->len, skb, len);

      shinfo = head + end;

      member_read(&gd->gso_size, shinfo, gso_size);
      member_read(&gd->gso_segs, shinfo, gso_segs);
      member_read(&gd->gso_type, shinfo, gso_type);

      return true;
    }
    """


def parse_data(data):
    gd = cast(data, POINTER(GSOData)).contents
    features = parse_features(gd.gso_type)
    return f" (len: {gd.len} gso_size: {gd.gso_size} gso_segs: {gd.gso_segs} gso_type: {features})"
