#!/usr/bin/env python3
"""Convert an Internet Topology Zoo GraphML file into a sparrowd topology file.

Link costs follow the OSPF auto-cost rule cost = reference_bandwidth / link_bandwidth
with a 100 Gbps reference. Edges with no capacity label get the network's most common
capacity (10 Gbps for GEANT 2012); duplicate edges between the same pair are merged
keeping the fastest one. Usage: zoo2topo.py in.graphml out.topo
"""
import collections
import re
import sys
import xml.etree.ElementTree as ET

NS = {"g": "http://graphml.graphdrawing.org/xmlns"}
REF_BPS = 100e9


def parse_bw(label):
    if not label:
        return None
    m = re.match(r"\s*([\d.]+)\s*([GMK])bps", label)
    if not m:
        return 100e9 if "fibre" in label.lower() else None  # dark/lit fibre: treat as 100G
    mult = {"G": 1e9, "M": 1e6, "K": 1e3}[m.group(2)]
    return float(m.group(1)) * mult


def main(src, dst):
    root = ET.parse(src).getroot()
    keys = {k.get("id"): k.get("attr.name") for k in root.findall("g:key", NS)}
    label_key = next(k for k, v in keys.items() if v == "label" and
                     root.find(f"g:key[@id='{k}']", NS).get("for") == "edge")
    name_key = next(k for k, v in keys.items() if v == "geocode_name")
    graph = root.find("g:graph", NS)
    nodes = graph.findall("g:node", NS)
    ids = {n.get("id"): i + 1 for i, n in enumerate(nodes)}
    names = {}
    for n in nodes:
        d = n.find(f"g:data[@key='{name_key}']", NS)
        names[ids[n.get("id")]] = (d.text or "").strip() if d is not None else ""
    raw = []
    for e in graph.findall("g:edge", NS):
        d = e.find(f"g:data[@key='{label_key}']", NS)
        raw.append((ids[e.get("source")], ids[e.get("target")], parse_bw(d.text if d is not None else None)))
    known = [bw for _, _, bw in raw if bw]
    default_bw = collections.Counter(known).most_common(1)[0][0]
    best = {}
    unlabeled = 0
    for a, b, bw in raw:
        if a == b:
            continue
        if bw is None:
            bw, unlabeled = default_bw, unlabeled + 1
        key = (min(a, b), max(a, b))
        best[key] = max(best.get(key, 0), bw)
    with open(dst, "w") as f:
        f.write(f"# GEANT 2012 from the Internet Topology Zoo ({src.split('/')[-1]})\n")
        f.write(f"# {len(nodes)} routers, {len(best)} links; cost = 100Gbps / capacity; "
                f"{unlabeled} unlabeled edges assumed {default_bw/1e9:g} Gbps\n")
        for i in sorted(names):
            f.write(f"node {i} {names[i].replace(' ', '_')}\n")
        for (a, b), bw in sorted(best.items()):
            f.write(f"link {a} {b} {max(1, round(REF_BPS / bw))}\n")
    print(f"{len(nodes)} nodes, {len(best)} links, {unlabeled} unlabeled -> {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
