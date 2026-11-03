#!/usr/bin/env python3
# Copyright (c) 2026 Suryansh Deshwal
# Licensed under the Apache License, Version 2.0
"""Summarize ipsec-baseline.sh output into summary.json and Markdown."""
import glob, json, os, re, statistics, sys

out = sys.argv[1]
S = {}

def nums(path):
    try:
        return [float(x) for x in open(path).read().split() if x.strip()]
    except FileNotFoundError:
        return []

def stats(v):
    if not v:
        return None
    v = sorted(v)
    pick = lambda p: v[min(len(v) - 1, int(round(p * (len(v) - 1))))]
    return {"n": len(v), "median": statistics.median(v), "mean": statistics.fmean(v),
            "min": v[0], "p95": pick(0.95), "max": v[-1],
            "stdev": statistics.stdev(v) if len(v) > 1 else 0.0}

for name in ["setup_ms", "list_sas_ms", "child_rekey_ms", "ike_rekey_ms", "reconnect_ms"]:
    S[name] = stats(nums(os.path.join(out, name + ".txt")))
for name in ["rss_idle_no_sa", "rss_with_sa", "rss_after_load"]:
    try:
        S[name + "_kb"] = json.load(open(os.path.join(out, name + ".json")))
    except FileNotFoundError:
        pass

def iperf(kind):
    vals, retr = [], []
    for f in sorted(glob.glob(os.path.join(out, f"iperf_{kind}_*.json"))):
        try:
            j = json.load(open(f))
            vals.append(j["end"]["sum_received"]["bits_per_second"] / 1e6)
            retr.append(j["end"]["sum_sent"].get("retransmits", 0))
        except Exception:
            pass
    return stats(vals), stats(retr)
S["throughput_base_mbps"], S["retransmits_base"] = iperf("base")
S["throughput_esp_mbps"], S["retransmits_esp"] = iperf("esp")

cpu = []
for f in sorted(glob.glob(os.path.join(out, "charon_cpu_esp_*.json"))):
    j = json.load(open(f))
    wall = j["wall_ms"] / 1000.0
    cpu.append({"a": j["a_ticks"] / j["hz"] / wall * 100, "b": j["b_ticks"] / j["hz"] / wall * 100})
if cpu:
    S["charon_cpu_pct_of_one_core_during_esp_iperf"] = {
        "a": stats([c["a"] for c in cpu]), "b": stats([c["b"] for c in cpu])}

rr = {}
for f in sorted(glob.glob(os.path.join(out, "rr_*_*.json"))):
    m = re.match(r"rr_(base|esp)_(\w+?)_(\d+)\.json", os.path.basename(f))
    if not m:
        continue
    try:
        j = json.loads(open(f).read().strip() or "{}")
    except json.JSONDecodeError:
        continue
    rr.setdefault(m.group(2), {}).setdefault(m.group(1), []).append(j)
S["request_response"] = {}
for prof, kinds in rr.items():
    S["request_response"][prof] = {}
    for kind, runs in kinds.items():
        S["request_response"][prof][kind] = {k: stats([r.get(k, 0) for r in runs]) for k in ["p50_us", "p95_us", "p99_us", "requests_per_sec"]}
        S["request_response"][prof][kind]["errors_total"] = sum(r.get("errors", 0) for r in runs)

lens = []
try:
    for line in open(os.path.join(out, "overhead.txt")):
        m = re.search(r"length (\d+):", line)
        if m:
            lens.append((line, int(m.group(1))))
except FileNotFoundError:
    pass
S["overhead_frames"] = [{"frame_len": l, "line": s.strip()[:160]} for s, l in lens]

env = {}
try:
    for line in open(os.path.join(out, "environment.txt")):
        if "=" in line:
            k, v = line.rstrip("\n").split("=", 1)
            env[k] = v
except FileNotFoundError:
    pass
S["environment"] = env
json.dump(S, open(os.path.join(out, "summary.json"), "w"), indent=2)

def f(st, k="median", d=1):
    return "-" if not st else f"{st[k]:.{d}f}"
print(f"## IPsec baseline ({env.get('family','?')})\n")
print("| metric | median | p95 | min | max | n |\n|---|---|---|---|---|---|")
for k, label in [("setup_ms", "IKE_SA+CHILD_SA(s) setup, ms"), ("child_rekey_ms", "CHILD_SA rekey, ms"),
                 ("ike_rekey_ms", "IKE_SA rekey, ms"), ("reconnect_ms", "terminate→first response, ms"),
                 ("list_sas_ms", "swanctl --list-sas, ms"), ("throughput_base_mbps", "TCP throughput no ESP, Mbit/s"),
                 ("throughput_esp_mbps", "TCP throughput ESP, Mbit/s")]:
    st = S.get(k)
    print(f"| {label} | {f(st)} | {f(st,'p95')} | {f(st,'min')} | {f(st,'max')} | {st['n'] if st else 0} |")
print()
for k in ["rss_idle_no_sa_kb", "rss_with_sa_kb", "rss_after_load_kb"]:
    if k in S:
        print(f"- charon {k}: {S[k]}")
if "charon_cpu_pct_of_one_core_during_esp_iperf" in S:
    c = S["charon_cpu_pct_of_one_core_during_esp_iperf"]
    print(f"- charon CPU during ESP iperf (% of one core, median): sender {f(c['a'])}, receiver {f(c['b'])}")
print("\n| profile | path | p50 µs | p95 µs | p99 µs | req/s | errors |\n|---|---|---|---|---|---|---|")
for prof, kinds in S["request_response"].items():
    for kind in ["base", "esp"]:
        if kind in kinds:
            r = kinds[kind]
            print(f"| {prof} | {kind} | {f(r['p50_us'])} | {f(r['p95_us'])} | {f(r['p99_us'])} | {f(r['requests_per_sec'],d=0)} | {r['errors_total']} |")
print()
for fr in S["overhead_frames"]:
    print(f"- frame {fr['frame_len']} B: {fr['line']}")
