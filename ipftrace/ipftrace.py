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
from ipftrace.modules import get_modules


# Protocol name <=> Protocol number mapping
PROTO_TO_ID = {}
ID_TO_PROTO = {}
def init_protocol_mapping():
    for line in open("/etc/protocols"):
        spl = line.split()
        if len(spl) == 0 or spl[0] == "#":
            continue
        PROTO_TO_ID[spl[2]] = spl[1]
        ID_TO_PROTO[spl[1]] = spl[2]


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
    l4_protocol: str
    saddr: str
    daddr: str
    sport: int = 0
    dport: int = 0

    def __str__(self):
        src = self.saddr + (":" + str(self.sport) if self.sport != 0 else "")
        dst = self.daddr + (":" + str(self.dport) if self.dport != 0 else "")
        return f"{self.l4_protocol}\t{src}\t->\t{dst}"


@dataclasses.dataclass(eq=True, frozen=True)
class EventLog:
    time_stamp: str
    event_name: str
    custom_data: str


class IPFTracer:
    def __init__(self, iv, saddr, daddr, proto,
            sport, dport, module, regex, length, manifest):
        self._opts = self._build_opts(iv, saddr, daddr, proto, sport, dport)
        self._functions = self._read_manifest(manifest)
        self._module = self._load_module(module)
        self._regex = regex
        self._length = length
        self._egress_functions = []
        self._flows = {}

    def _read_manifest(self, manifest):
        with open(manifest) as f:
            return yaml.load(f, Loader=yaml.FullLoader)["functions"]

    def _load_module(self, module):
        if module is None:
            return None

        modules = get_modules()
        module = modules[module]

        print("Loading module " + str(module))

        return module()

    def _inet_addr4(self, addr):
        a = ipaddress.IPv4Address(addr).packed
        return str(int.from_bytes(a, byteorder="little"))

    def _build_addr4_opt(self, addr, direction):
        if addr == "any":
            return ["-D", direction + "ADDRV4_ANY"]
        else:
            return ["-D", direction + "ADDRV4=" + self._inet_addr4(addr)]

    def _inet_addr6(self, addr):
        p = ipaddress.IPv6Address(addr).packed
        a = ",".join(list(map(lambda b: str(b), p)))
        return a

    def _build_addr6_opt(self, addr, direction):
        if addr == "any":
            return ["-D", direction + "ADDRV6_ANY"]
        else:
            return ["-D", direction + "ADDRV6=" + self._inet_addr6(addr)]

    def _build_ip_opt(self, iv, saddr, daddr):
        if iv == "4":
            ret = ["-D", "L3_PROTO=0x0008"]
            ret += self._build_addr4_opt(saddr, "S")
            ret += self._build_addr4_opt(daddr, "D")
        elif iv == "6":
            ret = ["-D", "L3_PROTO=0xdd86"]
            ret += self._build_addr6_opt(saddr, "S")
            ret += self._build_addr6_opt(daddr, "D")
        else:
            raise ValueError("Unknown IP version {}".format(iv))

        return ret

    def _build_proto_opt(self, proto):
        if proto == "any":
            return ["-D", "PROTO_ANY"]
        else:
            return ["-D", "PROTO=" + PROTO_TO_ID[proto]]

    def _build_port_opt(self, port, direction):
        if port == "any":
            return ["-D", direction + "PORT_ANY"]
        else:
            port = str(socket.htons(int(port)))
            return ["-D", direction + "PORT=" + port]

    def _build_opts(self, iv, saddr, daddr, proto, sport, dport):
        opts = []
        opts += self._build_ip_opt(iv, saddr, daddr)
        opts += self._build_proto_opt(proto)
        opts += self._build_port_opt(sport, "S")
        opts += self._build_port_opt(dport, "D")
        return opts

    def _build_probes(self):
        bpf_src = os.path.join(os.path.dirname(__file__), "ipftrace.bpf.c")
        ret = open(bpf_src).read()

        try:
            ret += self._module.gen_match()
        except:
            ret += textwrap.dedent(
                """
                static inline bool custom_match(void *ctx, struct sk_buff *skb, uint8_t *data) {
                  return true;
                }
                """
            )

        return ret

    def _attach_probes(self):
        probes = self._build_probes()
        b = BPF(text=probes, cflags=self._opts)

        for f in self._functions:
            name = f["name"]
            skb_pos = f["skb_pos"]

            if skb_pos > 4:
                print(f"Invalid skb_pos for function {name}. It should be lower than 4.")
                exit(1)

            if self._regex != None and not re.match(self._regex, name):
                continue

            try:
                b.attach_kprobe(event=name, fn_name=f"ipftrace_main{skb_pos}")
            except:
                print(f"Couldn't attach kprobe to function {name}")

            if f.get("egress", False):
                self._egress_functions.append(name)

        return b

    def list_functions(self):
        for f in self._functions:
            name = f["name"]
            if self._regex != None and not re.match(self._regex, name):
                continue
            print(f"{name}")

    def _parse_l3_proto(self, event):
        if event.l3_protocol == 0x0008:  # IPv4
            saddr = ipaddress.IPv4Address(socket.ntohl(event.addrs.v4.saddr))
            daddr = ipaddress.IPv4Address(socket.ntohl(event.addrs.v4.daddr))
        elif event.l3_protocol == 0xdd86:  # IPv6
            saddr = ipaddress.IPv6Address(bytes(event.addrs.v6.saddr))
            daddr = ipaddress.IPv6Address(bytes(event.addrs.v6.daddr))
        else:
            print(f"Unsupported l3 protocol {event.l3_protocol}")
            exit(1)

        return (str(saddr), str(daddr))

    def _parse_l4_proto(self, event):
        l4_proto = ID_TO_PROTO[str(event.l4_protocol)]
        sport = socket.ntohs(event.sport)
        dport = socket.ntohs(event.dport)
        return (l4_proto, sport, dport)

    def _parse_custom_data(self, event):
        if self._module != None:
            try:
                custom_data = self._module.parse_data(event.data)
            except Exception as e:
                print(e)
                custom_data = None
        else:
            custom_data = None

        return custom_data

    def _print_function_trace(self, flow, event_logs):
        if self._module != None:
            header = ["Time Stamp", "Function", "Custom Data"]
            table = [ [e.time_stamp, e.event_name, e.custom_data] for e in event_logs ]
        else:
            header = ["Time Stamp", "Function"]
            table = [ [e.time_stamp, e.event_name] for e in event_logs ]

        print(flow)
        print(tabulate.tabulate(table, header, tablefmt="plain"))
        print("")

    def _dump_unterminated_event_logs(self):
        print("======== Unterminated Flows ========")
        for flow, event_logs in self._flows.items():
            if len(event_logs) > 40:
                event_logs = event_logs[:39]
                trancate = True
            else:
                trancate = False

            self._print_function_trace(flow, event_logs)

            if trancate:
                print("<trancated...>\n")
        print("==== End of Unterminated Flows =====")

    def _handle_lost(self, lost):
        self._flows.clear()

    def _handle_event(self, cpu, data, size):
        event = cast(data, POINTER(EventData)).contents

        fname = BPF.ksym(event.faddr).decode("utf-8")
        tstamp = str(event.tstamp)
        saddr, daddr = self._parse_l3_proto(event)
        l4_proto, sport, dport = self._parse_l4_proto(event)
        custom_data = self._parse_custom_data(event)

        flow = Flow(
            l4_protocol=l4_proto,
            saddr=saddr,
            daddr=daddr,
            sport=sport,
            dport=dport,
        )

        event_logs = self._flows.get(flow, [])
        event_logs.append(EventLog(tstamp, fname, custom_data))
        self._flows[flow] = event_logs

        #
        # Print the function trace if it reaches to the length limit
        #
        if len(event_logs) == self._length:
            self._print_function_trace(flow, event_logs)
            del self._flows[flow]

        #
        # Print the function trace if it is terminated
        #
        if fname in self._egress_functions:
            self._print_function_trace(flow, event_logs)
            del self._flows[flow]

    def run_tracing(self):
        b = self._attach_probes()
        events = b["events"]

        events.open_perf_buffer(self._handle_event, lost_cb=self._handle_lost, page_cnt=64)

        print("Trace ready!")
        while 1:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                self._dump_unterminated_event_logs()
                print("Got keyboard interrupt. Detaching probes...")

                #
                # FIXME: b.clear() ends up to the exception on atexit handler.
                # So, we will release only kprobes in here.
                #
                for k, v in list(b.kprobe_fds.items()):
                    b.detach_kprobe_event(k)

                print("Finish detaching")
                return


@click.command()
@click.option("-iv", "--ipversion", default="4", type=click.Choice(["4", "6"]), help="Specify IP version")
@click.option("-s", "--saddr", default="any", help="Specify IP source address")
@click.option("-d", "--daddr", default="any", help="Specify IP destination address")
@click.option("-p", "--proto", default="any", help="Specify protocol")
@click.option("-sp", "--sport", default="any", help="Specify source port number")
@click.option("-dp", "--dport", default="any", help="Specify destination port number")
@click.option("-m", "--module", default=None, help="Specify custom match module name")
@click.option("-r", "--regex", default=None, help="Filter the function names by regex")
@click.option("-l", "--length", default=40, help="Specify the length of function trace")
@click.option("-ls", "--list-func", is_flag=True, help="List available functions")
@click.argument("manifest")
def main(ipversion, saddr, daddr, proto, sport, dport, module, regex, length, list_func, manifest):
    """
    Track the journey of the packets in Linux network stack
    """

    init_protocol_mapping()

    ift = IPFTracer(
        iv=ipversion,
        saddr=saddr,
        daddr=daddr,
        proto=proto,
        sport=sport,
        dport=dport,
        module=module,
        regex=regex,
        length=length,
        manifest=manifest
    )

    if list_func:
        ift.list_functions()
        exit(0)

    ift.run_tracing()


if __name__ == "__main__":
    main()
