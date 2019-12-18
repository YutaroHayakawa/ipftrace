#
# btf_to_manifest.py
#
# Extract the kernel functions which takes skb as an argument
# from BTF information and generate the ipftrace manifest file
#
# Usage:
# $ pahole -JV /lib/modules/`uname -r`/build/vmlinux
# $ bpftool -j btf dump file /lib/modules/`uname -r`/build/vmlinux | python btf_to_manifest.py
#

import sys
import json
import yaml
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


funcs = []
protos = []

j = json.load(sys.stdin)
for t in j["types"]:
    if t["kind"] == "FUNC":
        funcs.append(t)
    elif t["kind"] == "FUNC_PROTO":
        for i, p in enumerate(t["params"]):
            if p["name"] == "skb":
                protos.append({ "skb_pos": i + 1, "type_info": t })

ret = { "functions": [] }
for f in funcs:
    for p in protos:
        if p["type_info"]["id"] == f["type_id"]:
            if p["skb_pos"] > 4:
                continue
            ret["functions"].append({ "name": f["name"], "skb_pos": p["skb_pos"] })

print(yaml.dump(ret))
