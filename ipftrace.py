#
# Copyright (c) 2019 Yutaro Hayakawa
# Licensed under the Apache License, Version 2.0 (the "License")
#
import os
import re
import yaml
import click
import socket
import argparse
import textwrap
import tabulate
import importlib
import ipaddress
import subprocess
import dataclasses
from bcc import BPF
from ctypes import *


# Ethernet type name <=> Ethernet type mapping
L3_PROTO_TO_ID = {}
ID_TO_L3_PROTO = {}
def init_ethertypes_mapping():
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
def init_protocol_mapping():
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
        ("tstamp", c_uint64),
        ("faddr", c_uint64),
        ("l4_protocol", c_uint8),
        ("l3_protocol", c_uint16),
        ("addrs", IPAddrs),
        ("sport", c_uint16),
        ("dport", c_uint16),
        ("data", c_uint8 * 64),
    ]


@dataclasses.dataclass(eq=True, frozen=True)
class Flow:
    l3_protocol: str
    l4_protocol: str
    saddr: str
    daddr: str
    sport: int
    dport: int


@dataclasses.dataclass(eq=True, frozen=True)
class EventLog:
    time_stamp: str
    event_name: str
    custom_data: str


class IPFTracer:
    def __init__(self, **kwargs):
        self.args = kwargs
        self.functions = None
        self.egress_functions = []
        self.id_to_ename = []
        self.read_manifest()
        self.probes = self.build_probes()
        self.module = self.load_module()

    def read_manifest(self):
        with open(self.args["manifest_file"]) as f:
            self.functions = yaml.load(f, Loader=yaml.FullLoader)["functions"]

    def load_module(self):
        if self.args["module"] is None:
            return None
        return importlib.import_module(self.args["module"])

    def build_l3_protocol_opt(self, protocol):
        if protocol == "any":
            return ["-D", "L3_PROTOCOL_ANY"]
        else:
            return ["-D", "L3_PROTOCOL=" + L3_PROTO_TO_ID[protocol]]

    def build_l4_protocol_opt(self, protocol):
        if protocol == "any":
            return ["-D", "L4_PROTOCOL_ANY"]
        else:
            return ["-D", "L4_PROTOCOL=" + L4_PROTO_TO_ID[protocol]]

    def inet_addr4(self, addr):
        a = ipaddress.IPv4Address(addr).packed
        return str(int.from_bytes(a, byteorder="little"))

    def build_addr4_opt(self, addr, direction):
        if addr == "any":
            return ["-D", direction + "ADDRV4_ANY"]
        else:
            return ["-D", direction + "ADDRV4=" + self.inet_addr4(addr)]

    def inet_addr6(self, addr):
        p = ipaddress.IPv6Address(addr).packed
        a = ",".join(list(map(lambda b: str(b), p)))
        return a

    def build_addr6_opt(self, addr, direction):
        if addr == "any":
            return ["-D", direction + "ADDRV6_ANY"]
        else:
            return ["-D", direction + "ADDRV6=" + self.inet_addr6(addr)]


    def build_port_opt(self, port, direction):
        if port == "any":
            return ["-D", direction + "PORT_ANY"]
        else:
            return ["-D", direction + "PORT=" + port]

    def build_opts(self):
        opts = []
        opts += self.build_l3_protocol_opt(self.args["l3proto"])
        opts += self.build_l4_protocol_opt(self.args["l4proto"])
        opts += self.build_addr4_opt(self.args["saddr4"], "S")
        opts += self.build_addr4_opt(self.args["daddr4"], "D")
        opts += self.build_addr6_opt(self.args["saddr6"], "S")
        opts += self.build_addr6_opt(self.args["daddr6"], "D")
        opts += self.build_port_opt(self.args["sport"], "S")
        opts += self.build_port_opt(self.args["dport"], "D")
        return opts

    def build_probes(self):
        ret = open("ipftrace.bpf.c").read()

        try:
            ret += self.module.gen_match()
        except:
            ret += textwrap.dedent(
                """
                static inline bool custom_match(void *ctx, struct sk_buff *skb, uint8_t *data) {
                  return true;
                }
                """
            )

        return ret

    def attach_probes(self):
        probes = self.build_probes()
        opts = self.build_opts()
        b = BPF(text=probes, cflags=opts)

        for group, events in self.functions.items():
            for e in events:
                name = e["name"]
                skb_pos = e["skb_pos"]

                if skb_pos > 4:
                    print(f"Invalid skb_pos for function {name}. It should be lower than 4.")
                    exit(1)

                b.attach_kprobe(event=name, fn_name=f"ipftrace_main{skb_pos}")

                if e.get("egress", False):
                    self.egress_functions.append(name)

        return b

    def list_functions(self):
        for g, l in self.functions.items():
            print(g)
            for e in l:
                print(f"  {e['name']}")

    def run_tracing(self):
        b = self.attach_probes()
        events = b["events"]

        flows = {}

        #
        # In case of the lost, we should reset the flows, because we may
        # miss the egress events
        #
        def handle_lost(lost):
            flows.clear()

        def handle_event(cpu, data, size):
            event = cast(data, POINTER(EventData)).contents
            fname = BPF.ksym(event.faddr).decode("utf-8")
            tstamp = str(event.tstamp)

            if str(event.l3_protocol) == L3_PROTO_TO_ID["IPv4"]:
                saddr = ipaddress.IPv4Address(socket.ntohl(event.addrs.v4.saddr))
                daddr = ipaddress.IPv4Address(socket.ntohl(event.addrs.v4.daddr))
            elif str(event.l3_protocol) == L3_PROTO_TO_ID["IPv6"]:
                saddr = ipaddress.IPv6Address(bytes(event.addrs.v6.saddr))
                daddr = ipaddress.IPv6Address(bytes(event.addrs.v6.daddr))
            else:
                print(f"Unsupported l3 protocol {event.l3_protocol}")
                return

            l3_proto = ID_TO_L3_PROTO[str(event.l3_protocol)]
            l4_proto = ID_TO_L4_PROTO[str(event.l4_protocol)]
            sport = socket.ntohs(event.sport)
            dport = socket.ntohs(event.dport)

            flow = Flow(
                l3_protocol=l3_proto,
                l4_protocol=l4_proto,
                saddr=str(saddr),
                daddr=str(daddr),
                sport=sport,
                dport=dport,
            )

            event_logs = flows.get(flow, [])

            if self.module != None:
                try:
                    custom_data = self.module.parse_data(event.data)
                except Exception as e:
                    custom_data = None
            else:
                custom_data = None

            event_logs.append(EventLog(tstamp, fname, custom_data))

            flows[flow] = event_logs

            if fname in self.egress_functions:
                src = str(saddr) + (":" + str(sport) if sport != 0 else "")
                dst = str(daddr) + (":" + str(dport) if dport != 0 else "")
                if self.module != None:
                    header = ["Time Stamp", "Function", "Custom Data"]
                    table = [ [e.time_stamp, e.event_name, e.custom_data] for e in event_logs ]
                else:
                    header = ["Time Stamp", "Function"]
                    table = [ [e.time_stamp, e.event_name] for e in event_logs ]
                print(f"{l4_proto}\t{src}\t->\t{dst}")
                print(tabulate.tabulate(table, header, tablefmt="plain"))
                print("")
                del flows[flow]

        events.open_perf_buffer(handle_event, lost_cb=handle_lost, page_cnt=64)

        print("Trace ready!")
        while 1:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit(0)

@click.command()
@click.option("-iv", "--ipversion", default="any", type=click.Choice(["any", "4", "6"]), help="Specify IP version")
@click.option("-l4", "--l4proto", default="any", help="Specify L4 protocol")
@click.option("-s4", "--saddr4", default="any", help="Specify IPv4 source address")
@click.option("-d4", "--daddr4", default="any", help="Specify IPv4 destination address")
@click.option("-s6", "--saddr6", default="any", help="Specify IPv6 source address")
@click.option("-d6", "--daddr6", default="any", help="Specify IPv6 destination address")
@click.option("-sp", "--sport", default="any", help="Specify source port number")
@click.option("-dp", "--dport", default="any", help="Specify destination port number")
@click.option("-m", "--module", default=None, help="Specify custom match module name")
@click.option("-l", "--list", is_flag=True, help="List available groups and functions")
@click.argument("manifest-file")
def main(ipversion, l4proto, saddr4, daddr4, saddr6, daddr6, sport, dport, module, list, manifest_file):
    """
    Track the journey of the packets in Linux L3 layer
    """

    if ipversion == "any":
        l3proto = "any"
    else:
        l3proto = "IPv" + ipversion

    ift = IPFTracer(
        l3proto=l3proto,
        l4proto=l4proto,
        saddr4=saddr4,
        daddr4=daddr4,
        saddr6=saddr6,
        daddr6=daddr6,
        sport=sport,
        dport=dport,
        module=module,
        manifest_file=manifest_file
    )

    if list:
        ift.list_functions()
        exit(0)

    init_ethertypes_mapping()
    init_protocol_mapping()

    ift.run_tracing()


if __name__ == "__main__":
    main()
