#
# Copyright (c) 2019 Yutaro Hayakawa
# Licensed under the Apache License, Version 2.0 (the "License")
#
from bcc import BPF
from ctypes import *
import json
import socket
import argparse
import textwrap
import ipaddress
import dataclasses


EVENTS = None


# Event ID <=> Event name mapping
EID_TO_ENAME = []


# Ethernet type name <=> Ethernet type mapping
L3_PROTO_TO_ID = {}
ID_TO_L3_PROTO = {}
for line in open("/etc/ethertypes"):
    spl = line.split()
    if len(spl) == 0 or spl[0] == "#":
        continue
    ident = str(socket.htons(int(spl[1], 16)))
    L3_PROTO_TO_ID[spl[0]] = ident
    ID_TO_L3_PROTO[ident] = spl[0]


# Protocol name <=> Protocol number mapping
L4_PROTO_TO_ID = {}
ID_TO_L4_PROTO = {}
for line in open("/etc/protocols"):
    spl = line.split()
    if len(spl) == 0 or spl[0] == "#":
        continue
    L4_PROTO_TO_ID[spl[2]] = spl[1]
    ID_TO_L4_PROTO[spl[1]] = spl[2]


class V4Addrs(Structure):
    _fields_ = [("saddr", c_uint32), ("daddr", c_uint32)]


class V6Addrs(Structure):
    _fields_ = [("saddr", c_uint8 * 16), ("daddr", c_uint8 * 16)]


class IPAddrs(Union):
    _fields_ = [("v4", V4Addrs), ("v6", V6Addrs)]


class EventData(Structure):
    _anonymous = "addrs"
    _fields_ = [
        ("event_id", c_uint8),
        ("l4_protocol", c_uint8),
        ("l3_protocol", c_uint16),
        ("addrs", IPAddrs),
        ("sport", c_uint16),
        ("dport", c_uint16),
    ]


@dataclasses.dataclass(eq=True, frozen=True)
class Flow:
    l3_protocol: str
    l4_protocol: str
    saddr: str
    daddr: str
    sport: int
    dport: int


def build_l3_protocol_opt(protocol):
    if protocol == "any":
        return ["-D", "L3_PROTOCOL_ANY"]
    else:
        return ["-D", "L3_PROTOCOL=" + L3_PROTO_TO_ID[protocol]]


def build_l4_protocol_opt(protocol):
    if protocol == "any":
        return ["-D", "L4_PROTOCOL_ANY"]
    else:
        return ["-D", "L4_PROTOCOL=" + L4_PROTO_TO_ID[protocol]]


def inet_addr4(addr):
    a = ipaddress.IPv4Address(addr).packed
    return str(int.from_bytes(a, byteorder="little"))


def build_addr4_opt(addr, direction):
    if addr == "any":
        return ["-D", direction + "ADDRV4_ANY"]
    else:
        return ["-D", direction + "ADDRV4=" + inet_addr4(addr)]


def inet_addr6(addr):
    p = ipaddress.IPv6Address(addr).packed
    a = ",".join(list(map(lambda b: str(b), p)))
    return a


def build_addr6_opt(addr, direction):
    if addr == "any":
        return ["-D", direction + "ADDRV6_ANY"]
    else:
        return ["-D", direction + "ADDRV6=" + inet_addr6(addr)]


def build_port_opt(port, direction):
    if port == "any":
        return ["-D", direction + "PORT_ANY"]
    else:
        return ["-D", direction + "PORT=" + port]


def build_probes():
    eid = 0
    ret = open("iptrace.bpf.c").read()
    for group in EVENTS.values():
        for e in group:
            EID_TO_ENAME.append(e["name"])
            probe = textwrap.dedent(
                f"""
                void kprobe__{e['name']}({ ', '.join(['struct pt_regs *ctx'] + e['args']) }) {{
                  struct event_data e = {{ {eid} }};
                  if (!match(ctx, skb, &e)) {{
                    return;
                  }}
                  action(ctx, &e);
                }}
                """
            )
            ret += probe
            eid += 1

    return ret


def list_events(event_file):
    print("Available events")
    for n, g in EVENTS.items():
        print(n)
        for e in g:
            print(f"  {e['name']}")


def exclude_event_groups(classes):
    spl = classes.split(",")
    for c in spl:
        del EVENTS[c]


# Arguments
examples = """examples:
    ./iptrace                                       # trace all flow
    ./iptrace --l3proto IPv4 --saddr4 10.0.1.10     # filter by source address
    ./iptrace --l4proto ICMP --saddr4 10.0.1.10     # filter by upper protocol
"""
parser = argparse.ArgumentParser(
    description="Track the journey of the packets inside the IP layer",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)
parser.add_argument(
    "-l3", "--l3proto", default="any", help="Specify L3 protocol (IPv4 or IPv6)"
)
parser.add_argument(
    "-l4",
    "--l4proto",
    default="any",
    help="Specify L4 protocol (Any protocols in /etc/protocols)",
)
parser.add_argument(
    "-s4", "--saddr4", default="any", help="Specify source IPv4 address"
)
parser.add_argument(
    "-d4", "--daddr4", default="any", help="Specify destination IPv4 address"
)
parser.add_argument(
    "-s6", "--saddr6", default="any", help="Specify source IPv6 address"
)
parser.add_argument(
    "-d6", "--daddr6", default="any", help="Specify destination IPv6 address"
)
parser.add_argument("-sp", "--sport", default="any", help="Specify source port number")
parser.add_argument(
    "-dp", "--dport", default="any", help="Specify destination port number"
)
parser.add_argument(
    "-e", "--exclude", help="Exclude specific event groups (comma separated)"
)
parser.add_argument(
    "-f",
    "--event-file",
    default="./events.json",
    help="Specify event file (default: ./events.json",
)
parser.add_argument(
    "-l", "--list-events", action="store_true", help="List available events"
)
parser.add_argument("-d", "--debug", action="store_true")
args = parser.parse_args()

# Read all events
with open(args.event_file) as f:
    EVENTS = json.load(f)["events"]

# Exclude specific classes
if args.exclude != None:
    exclude_event_groups(args.exclude)

# List available events and finish
if args.list_events:
    list_events(args.event_file)
    exit(0)

# Build -D options
opts = []
opts += build_l3_protocol_opt(args.l3proto)
opts += build_l4_protocol_opt(args.l4proto)
opts += build_addr4_opt(args.saddr4, "S")
opts += build_addr4_opt(args.daddr4, "D")
opts += build_addr6_opt(args.saddr6, "S")
opts += build_addr6_opt(args.daddr6, "D")
opts += build_port_opt(args.sport, "S")
opts += build_port_opt(args.dport, "D")

if args.debug:
    print("CFlags: " + str(opts))

# Build kprobes
probes = build_probes()
if args.debug:
    print("Probes")
    print(probes)

# Attach probes
b = BPF(text=probes, cflags=opts)
events = b["events"]

flows = {}


def handle_event(cpu, data, size):
    event = cast(data, POINTER(EventData)).contents
    event_name = EID_TO_ENAME[event.event_id]

    if str(event.l3_protocol) == L3_PROTO_TO_ID["IPv4"]:
        saddr = ipaddress.IPv4Address(socket.ntohl(event.addrs.v4.saddr))
        daddr = ipaddress.IPv4Address(socket.ntohl(event.addrs.v4.daddr))
    elif str(event.l3_protocol) == L3_PROTO_TO_ID["IPv6"]:
        saddr = ipaddress.IPv6Address(bytes(event.addrs.v6.saddr))
        daddr = ipaddress.IPv6Address(bytes(event.addrs.v6.daddr))
    else:
        print(f"Unsupported l3 protocol {event.l3_protocol}")
        return

    flow = Flow(
        l3_protocol=ID_TO_L3_PROTO[str(event.l3_protocol)],
        l4_protocol=ID_TO_L4_PROTO[str(event.l4_protocol)],
        saddr=str(saddr),
        daddr=str(daddr),
        sport=socket.ntohs(event.sport),
        dport=socket.ntohs(event.dport),
    )

    event_list = flows.get(flow, [])
    if event_name not in event_list:
        event_list.append(event_name)

    flows[flow] = event_list


events.open_perf_buffer(handle_event, page_cnt=64)

print("Trace ready!")
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit(0)

    for f, e in flows.items():
        proto = f.l4_protocol
        src = f.saddr + ((":" + str(f.sport)) if f.sport != 0 else "")
        dst = f.daddr + ((":" + str(f.dport)) if f.dport != 0 else "")
        print(f"{proto}\t{src}\t->\t{dst}\t{e}")
