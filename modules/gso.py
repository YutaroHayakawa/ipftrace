from ctypes import *


def gen_match():
    return """
    struct gso_data {
      unsigned short gso_size;
      unsigned short gso_segs;
      unsigned int gso_type;
    };

    static inline bool
    custom_match(void *ctx, struct sk_buff *skb, uint8_t *data) {
      void *head;
      sk_buff_data_t end;
      struct skb_shared_info *shinfo;
      struct gso_data *gd = (struct gso_data *)data;

      member_read(&head, skb, head);
      member_read(&end, skb, end);

      shinfo = head + end;

      member_read(&gd->gso_size, shinfo, gso_size);
      member_read(&gd->gso_segs, shinfo, gso_segs);
      member_read(&gd->gso_type, shinfo, gso_type);

      return true;
    }
    """


class GSOData(Structure):
    _fields_ = [
        ("gso_size", c_ushort),
        ("gso_segs", c_ushort),
        ("gso_type", c_uint),
    ]


def parse_data(data):
    gd = cast(data, POINTER(GSOData)).contents
    return f" (gso_size: {gd.gso_size} gso_segs: {gd.gso_segs} gso_type: {gd.gso_type})"
