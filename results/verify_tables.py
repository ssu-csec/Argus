#!/usr/bin/env python3
"""
verify_tables.py  —  Reproduce and verify every number in the Argus paper.

Usage:
    python3 verify_tables.py              # Verify paper numbers match CSV
    python3 verify_tables.py --compute    # Print CSV-computed values only (no comparison)
    python3 verify_tables.py --tex        # Cross-check all tex files for stale numbers

Exit code:
    0  all checks passed
    1  at least one mismatch (or tex inconsistency)

Input files (same directory as this script):
    combined_1-100000.csv   — main measurement data
    gt_result.csv           — ground-truth validation data

Counting conventions (matching the paper's pipeline):
  - Table 5 (rule complexity): counts explicit "(Rule N)" markers in Threat_Type.
    Every route classified as a mixed-tracker carries at least one such marker;
    Fingerprinting_Leak is the one exception (Rule 5 sub-type without an explicit marker).
  - Table 6 R4: identified by sink label "Evasion Suspected", not Threat_Type.
  - Table 6 R5 total: |Deterministic ∪ Probabilistic| only; Device Data Leak
    (Fingerprinting_Leak) is listed as sub-category but EXCLUDED from the total.
  - Table 8 createElement: only createElement().href counts as "Element creation";
    createElement().src (87 routes) goes to "Other DOM sinks".
  - Table 9 CNAME beneficiaries: counted across ALL route classes
    (Mixed Tracker + R3-only + Tracker-only), not Mixed Tracker only.
  - Table 3/6 R5 total: |Det ∪ Prob| only; Device Data Leak excluded from total.
"""

import csv
import re
import os
import sys
import glob as globmod
import hashlib
import argparse
from collections import Counter, defaultdict
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_CSV = os.path.join(SCRIPT_DIR, "combined_1-100000.csv")
GT_CSV = os.path.join(SCRIPT_DIR, "gt_result.csv")
TOTAL_ANALYZED = 52970  # Unique domains in CSV's [Per-Domain Mixed Tracker Evidence] section.
                        # = 12,403 (Mixed) + 1,076 (Partial: R3 Only + Tracker Only) + 39,491 (no rule).
                        # Earlier value 66,449 was a double-count (52,970 + 13,479).

# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════

parser = argparse.ArgumentParser(
    description="Verify Argus paper numbers against CSV data.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=__doc__,
)
parser.add_argument("--compute", action="store_true",
                    help="Print all computed values (no comparison mode)")
parser.add_argument("--tex", action="store_true",
                    help="Cross-check tex files for stale/mismatched numbers")
args = parser.parse_args()

MODE_COMPUTE = args.compute
MODE_TEX = args.tex

# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def pct(n, d):
    """Percentage rounded to 1 decimal place."""
    return round(n / d * 100, 1) if d else 0.0


def md5_file(path):
    """Return MD5 hex digest of a file (for traceability)."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Result tracking ──────────────────────────────────────────────────

pass_count = 0
fail_count = 0
results = []        # list of (section, label, computed, expected, ok)
current_section = ""

def section(title):
    """Set the current section for result tracking."""
    global current_section
    current_section = title
    if not MODE_TEX:
        print(f"\n{'=' * 70}")
        print(title)
        print("=" * 70)


def check(label, computed, expected):
    """Compare computed vs expected; track and print result."""
    global pass_count, fail_count
    ok = (computed == expected)
    results.append((current_section, label, computed, expected, ok))

    if MODE_TEX:
        pass  # silent — tex mode handles its own output
    elif MODE_COMPUTE:
        print(f"  {label}: {computed}")
    else:
        tag = "OK" if ok else "*** MISMATCH ***"
        print(f"  {label}: computed={computed}, paper={expected}  {tag}")

    if ok:
        pass_count += 1
    else:
        fail_count += 1
    return ok


# ── Rule detection helpers ───────────────────────────────────────────

def parse_rules_explicit(tt):
    """Count rules by explicit (Rule N) markers in the Threat_Type field."""
    rules = set()
    for m in re.findall(r'\(Rule (\d)\)', tt):
        rules.add(f"R{m}")
    # Fingerprinting_Leak is a Rule 5 sub-type whose label omits the explicit marker.
    if "Fingerprinting_Leak" in tt:
        rules.add("R5")
    return rules


def has_r5(tt):     return "Rule 5" in tt or "Fingerprinting_Leak" in tt
def has_r4_sink(s): return "Evasion Suspected" in s
def has_r4_hid(tt): return "Dynamic Obfuscated" in tt
def has_r3(tt):     return "Rule 3" in tt or "Dual_Execution_Context" in tt
def has_r2(tt):     return "Rule 2" in tt or "Parasitic_Branch" in tt
def has_r1(tt):     return "Rule 1" in tt or "Isolated_Exfiltration" in tt


# ═══════════════════════════════════════════════════════════════════════
# Load CSV data
# ═══════════════════════════════════════════════════════════════════════

def load_main_csv():
    """Load and classify rows from combined_1-100000.csv."""
    mk, mn, r3o, to, allr = [], [], [], [], []

    with open(MAIN_CSV, "r", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            tc = row.get("Tracker_Class")
            if tc is None or tc.startswith("Routes:"):
                continue
            row["Domain"] = row["Domain"].strip()
            if tc == "Mixed Tracker - Known":
                mk.append(row)
            elif tc in ("Mixed Tracker - Unknown", "Mixed Tracker - Novel"):
                mn.append(row)
            elif tc.startswith("R3 Only"):
                r3o.append(row)
            elif tc.startswith("Tracker Only"):
                to.append(row)
            allr.append(row)

    return mk, mn, r3o, to, allr


def load_gt_csv():
    """Load ground-truth validation rows from gt_result.csv."""
    rows = []
    with open(GT_CSV, "r", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if row.get("Tracker_Class") is None:
                continue
            row["Domain"] = row["Domain"].strip()
            rows.append(row)
    return rows


print(f"Loading data...  ({datetime.now().strftime('%Y-%m-%d %H:%M')})")
print(f"  Main CSV hash: {md5_file(MAIN_CSV)}")
print(f"  GT CSV hash:   {md5_file(GT_CSV)}")

mixed_known_rows, mixed_novel_rows, r3_only_rows, tracker_only_rows, all_route_rows = load_main_csv()
gt_rows = load_gt_csv()

mixed_rows = mixed_known_rows + mixed_novel_rows
all_classified_rows = mixed_rows + r3_only_rows + tracker_only_rows

mixed_known_domains = set(r["Domain"] for r in mixed_known_rows)
# Novel domains are mutually exclusive with Known: a domain with ANY Known route is Known.
# 3 domains have routes in both classes; we count those domains as Known.
# Routes (row-level Tracker_Class) keep their original labels regardless of domain category.
mixed_novel_domains = set(r["Domain"] for r in mixed_novel_rows) - mixed_known_domains
mixed_domains = mixed_known_domains | mixed_novel_domains
r3_only_domains = set(r["Domain"] for r in r3_only_rows) - mixed_domains
tracker_only_domains = set(r["Domain"] for r in tracker_only_rows) - mixed_domains

print(f"  Mixed: {len(mixed_rows)} routes ({len(mixed_domains)} domains)")
print(f"  R3-only: {len(r3_only_rows)},  Tracker-only: {len(tracker_only_rows)}")
print(f"  All classified: {len(all_classified_rows)},  Ground truth: {len(gt_rows)}")


# ═══════════════════════════════════════════════════════════════════════
# TABLE 3: Ground-truth validation
# ═══════════════════════════════════════════════════════════════════════

def verify_table3():
    section("TABLE 3: Ground-truth validation (tab:gt-rules)")

    gt_mixed = [r for r in gt_rows if r["Tracker_Class"].startswith("Mixed Tracker")]
    gt_mixed_domains = set(r["Domain"] for r in gt_mixed)

    check("Mixed-tracker domains", len(gt_mixed_domains), 36)
    check("Mixed-tracker routes", len(gt_mixed), 237)

    rd = {"R1": {"d": set(), "r": 0}, "R2": {"d": set(), "r": 0},
          "R3": {"d": set(), "r": 0},
          "R4": {"d": set(), "r": 0},
          "R5": {"d": set(), "r": 0, "det": 0, "prob": 0, "dev": 0}}

    r4_id = r4_hid = 0

    for r in gt_mixed:
        tt = r["Threat_Type"]
        d = r["Domain"]
        sink = r.get("Leak_Method (Sink)", "")

        if has_r1(tt): rd["R1"]["d"].add(d); rd["R1"]["r"] += 1
        if has_r2(tt): rd["R2"]["d"].add(d); rd["R2"]["r"] += 1
        if has_r3(tt): rd["R3"]["d"].add(d); rd["R3"]["r"] += 1

        if has_r4_sink(sink):
            rd["R4"]["d"].add(d); rd["R4"]["r"] += 1
            if has_r4_hid(tt):
                r4_hid += 1
            else:
                r4_id += 1

        if has_r5(tt):
            rd["R5"]["d"].add(d)
            if "Deterministic" in tt:
                rd["R5"]["det"] += 1
                rd["R5"]["r"] += 1          # R5 total = |Det ∪ Prob|
            elif "Fingerprinting_Leak" in tt:
                rd["R5"]["dev"] += 1         # Device Leak excluded from total
            else:
                rd["R5"]["prob"] += 1
                rd["R5"]["r"] += 1           # R5 total = |Det ∪ Prob|

    check("R3 domains", len(rd["R3"]["d"]), 36)
    check("R3 routes", rd["R3"]["r"], 235)
    check("R4 domains", len(rd["R4"]["d"]), 36)
    check("R4 routes", rd["R4"]["r"], 144)
    check("R4 dest identified", r4_id, 49)
    check("R4 dest hidden", r4_hid, 95)
    check("R5 domains", len(rd["R5"]["d"]), 34)
    check("R5 routes", rd["R5"]["r"], 127)
    check("R5 deterministic", rd["R5"]["det"], 40)
    check("R5 probabilistic", rd["R5"]["prob"], 87)
    check("R5 device leak", rd["R5"]["dev"], 2)
    check("R2 domains", len(rd["R2"]["d"]), 8)
    check("R2 routes", rd["R2"]["r"], 18)
    check("R1 domains", len(rd["R1"]["d"]), 3)
    check("R1 routes", rd["R1"]["r"], 4)

    gt_ge4 = sum(1 for r in gt_mixed if int(r.get("Confidence_Score", 0)) >= 4)
    check("Score>=4 routes", gt_ge4, 134)
    check("Score>=4 %", pct(gt_ge4, len(gt_mixed)), 56.5)


# ═══════════════════════════════════════════════════════════════════════
# TABLE 4: Mixed-tracker classification
# ═══════════════════════════════════════════════════════════════════════

def verify_table4():
    section("TABLE 4: Mixed-tracker classification (tab:classification)")

    check("Mixed Tracker domains", len(mixed_domains), 12403)
    check("Mixed Tracker %", pct(len(mixed_domains), TOTAL_ANALYZED), 23.4)
    check("Known domains", len(mixed_known_domains), 10122)
    check("Known %", pct(len(mixed_known_domains), TOTAL_ANALYZED), 19.1)
    check("Novel domains", len(mixed_novel_domains), 2281)
    check("Novel %", pct(len(mixed_novel_domains), TOTAL_ANALYZED), 4.3)

    partial = len(r3_only_domains) + len(tracker_only_domains)
    check("Partial: R3 Only", len(r3_only_domains), 746)
    check("Partial: Tracker Only", len(tracker_only_domains), 330)
    check("Partial total", partial, 1076)

    no_rule = TOTAL_ANALYZED - len(mixed_domains) - partial
    check("No rule triggered", no_rule, 39491)

    not_classified = partial + no_rule
    check("Not classified (merged)", not_classified, 40567)
    check("Not classified %", pct(not_classified, TOTAL_ANALYZED), 76.6)
    check("Mixed routes total", len(mixed_rows), 64503)
    check("Avg routes/domain", round(len(mixed_rows) / len(mixed_domains), 1), 5.2)
    check("Known % of mixed", pct(len(mixed_known_domains), len(mixed_domains)), 81.6)
    check("Novel % of mixed", pct(len(mixed_novel_domains), len(mixed_domains)), 18.4)


# ═══════════════════════════════════════════════════════════════════════
# TABLE: Routes-per-domain distribution
# ═══════════════════════════════════════════════════════════════════════

def verify_routes_per_domain():
    section("TABLE: Routes-per-domain distribution (tab:routes-per-domain)")

    dom_cnt = Counter(r["Domain"] for r in mixed_rows)
    md = len(mixed_domains)
    mr = len(mixed_rows)

    import statistics
    vals = list(dom_cnt.values())
    check("Median routes/domain", int(statistics.median(vals)), 4)
    check("Max routes/domain", max(vals), 38)

    for lo, hi, exp_d, exp_dp, exp_r, exp_rp in [
        (1,  1,   981,  7.9,   981,  1.5),
        (2,  3,  4090, 33.0, 10235, 15.9),
        (4,  5,  2915, 23.5, 12884, 20.0),
        (6,  10, 3275, 26.4, 24628, 38.2),
        (11, 20, 1088,  8.8, 14475, 22.4),
        (21, 50,   54,  0.4,  1300,  2.0),
    ]:
        ds = [d for d, c in dom_cnt.items() if lo <= c <= hi]
        rs = sum(dom_cnt[d] for d in ds)
        label = f"{lo}" if lo == hi else f"{lo}-{hi}"
        check(f"Bin {label} domains", len(ds), exp_d)
        check(f"Bin {label} domains %", pct(len(ds), md), exp_dp)
        check(f"Bin {label} routes", rs, exp_r)
        check(f"Bin {label} routes %", pct(rs, mr), exp_rp)


# ═══════════════════════════════════════════════════════════════════════
# TABLE 5: Evasion complexity
# ═══════════════════════════════════════════════════════════════════════

def verify_table5():
    section("TABLE 5: Evasion complexity (tab:rule-complexity)\n"
            "  Counting: explicit (Rule N) markers only")

    known_rc = Counter()
    novel_rc = Counter()
    for r in mixed_known_rows:
        known_rc[len(parse_rules_explicit(r["Threat_Type"]))] += 1
    for r in mixed_novel_rows:
        novel_rc[len(parse_rules_explicit(r["Threat_Type"]))] += 1

    kt = sum(known_rc.values())
    nt = sum(novel_rc.values())

    for n, exp_k, exp_kp, exp_n, exp_np in [
        (1, 16003, 29.7, 3317, 31.0),
        (2, 11533, 21.4, 6436, 60.1),
        (3, 24321, 45.2, 922,  8.6),
        (4, 1946,  3.6,  25,   0.2),
    ]:
        check(f"Known {n} rule(s)", known_rc[n], exp_k)
        check(f"Known {n} rule(s) %", pct(known_rc[n], kt), exp_kp)
        check(f"Novel {n} rule(s)", novel_rc[n], exp_n)
        check(f"Novel {n} rule(s) %", pct(novel_rc[n], nt), exp_np)

    k_ge2 = sum(v for k, v in known_rc.items() if k >= 2)
    n_ge2 = sum(v for k, v in novel_rc.items() if k >= 2)
    check("Known >=2", k_ge2, 37800)
    check("Known >=2 %", pct(k_ge2, kt), 70.3)
    check("Novel >=2", n_ge2, 7383)
    check("Novel >=2 %", pct(n_ge2, nt), 69.0)


# ═══════════════════════════════════════════════════════════════════════
# TABLE 6: Evasion technique distribution
# ═══════════════════════════════════════════════════════════════════════

def verify_table6():
    section("TABLE 6: Evasion technique distribution (tab:rule-dist)\n"
            "  R3 base=all classified; R4-R1 base=mixed only\n"
            "  R5 total = |Det ∪ Prob|, Device Leak listed separately")

    mr = len(mixed_rows)

    # R3 (mixed only — table no longer includes R3-only/Tracker-only)
    r3_c = sum(1 for r in mixed_rows if has_r3(r["Threat_Type"]))
    check("R3 routes (mixed)", r3_c, 63613)
    check("R3 %", pct(r3_c, mr), 98.6)

    # R4 (by sink label, not Threat_Type)
    r4_total = sum(1 for r in mixed_rows if has_r4_sink(r["Leak_Method (Sink)"]))
    r4_hid = sum(1 for r in mixed_rows
                 if has_r4_sink(r["Leak_Method (Sink)"]) and has_r4_hid(r["Threat_Type"]))
    r4_id = r4_total - r4_hid

    check("R4 routes", r4_total, 41287)
    check("R4 %", pct(r4_total, mr), 64.0)
    check("R4 dest identified", r4_id, 2370)
    check("R4 dest id %", pct(r4_id, mr), 3.7)
    check("R4 dest hidden", r4_hid, 38917)
    check("R4 dest hid %", pct(r4_hid, mr), 60.3)

    # R5: total = |Det ∪ Prob| (excludes Device Leak)
    r5_det = set()
    r5_prob = set()
    r5_dev = 0
    for i, r in enumerate(mixed_rows):
        tt = r["Threat_Type"]
        if "Deterministic" in tt and ("Rule 5" in tt or "Semantic_CrossValidation" in tt):
            r5_det.add(i)
        if "Probabilistic" in tt and ("Rule 5" in tt or "Semantic_CrossValidation" in tt):
            r5_prob.add(i)
        if "Fingerprinting_Leak" in tt:
            r5_dev += 1

    r5_overlap = r5_det & r5_prob
    # Make D and P mutually exclusive: assign overlap routes to D (stronger evidence).
    r5_prob = r5_prob - r5_det
    r5_union = r5_det | r5_prob

    check("R5 total (|Det∪Prob|)", len(r5_union), 26305)
    check("R5 %", pct(len(r5_union), mr), 40.8)
    check("R5 deterministic", len(r5_det), 1600)
    check("R5 det %", pct(len(r5_det), mr), 2.5)
    check("R5 probabilistic", len(r5_prob), 24705)
    check("R5 prob %", pct(len(r5_prob), mr), 38.3)
    check("R5 device leak", r5_dev, 1114)
    check("R5 dev %", pct(r5_dev, mr), 1.7)
    if not MODE_TEX:
        print(f"  [INFO] R5 Det∩Prob overlap: {len(r5_overlap)}")

    # R2, R1
    r2_c = sum(1 for r in mixed_rows if has_r2(r["Threat_Type"]))
    r1_c = sum(1 for r in mixed_rows if has_r1(r["Threat_Type"]))
    check("R2 routes", r2_c, 5080)
    check("R2 %", pct(r2_c, mr), 7.9)
    check("R1 routes", r1_c, 1498)
    check("R1 %", pct(r1_c, mr), 2.3)

    # ── Domain-level columns (Table 6) ──
    md = len(mixed_domains)
    r3_d = set(r["Domain"] for r in mixed_rows if has_r3(r["Threat_Type"]))
    r4_d = set(r["Domain"] for r in mixed_rows
               if has_r4_sink(r.get("Leak_Method (Sink)", "")))
    r5_det_d = set(r["Domain"] for r in mixed_rows
                   if "Deterministic" in r["Threat_Type"]
                   and ("Rule 5" in r["Threat_Type"]
                        or "Semantic_CrossValidation" in r["Threat_Type"]))
    r5_prob_d = set(r["Domain"] for r in mixed_rows
                    if "Probabilistic" in r["Threat_Type"]
                    and ("Rule 5" in r["Threat_Type"]
                         or "Semantic_CrossValidation" in r["Threat_Type"]))
    r5_d = r5_det_d | r5_prob_d
    r2_d = set(r["Domain"] for r in mixed_rows if has_r2(r["Threat_Type"]))
    r1_d = set(r["Domain"] for r in mixed_rows if has_r1(r["Threat_Type"]))

    check("R3 domains", len(r3_d), 12403)
    check("R3 dom %", pct(len(r3_d), md), 100.0)
    check("R4 domains", len(r4_d), 12222)
    check("R4 dom %", pct(len(r4_d), md), 98.5)
    check("R5 domains (Det∪Prob)", len(r5_d), 8091)
    check("R5 dom %", pct(len(r5_d), md), 65.2)
    check("R2 domains", len(r2_d), 2047)
    check("R2 dom %", pct(len(r2_d), md), 16.5)
    check("R1 domains", len(r1_d), 1315)
    check("R1 dom %", pct(len(r1_d), md), 10.6)

    # Store for body-text checks
    return r4_total, r4_hid


# ═══════════════════════════════════════════════════════════════════════
# TABLE 7: Trigger context distribution
# ═══════════════════════════════════════════════════════════════════════

def verify_table7():
    section("TABLE 7: Trigger context distribution (tab:trigger-context)")

    def ctx(rows):
        a = sum(1 for r in rows if r["Trigger_Context"] == "AUTONOMOUS")
        e = sum(1 for r in rows if r["Trigger_Context"] == "EVENT_DRIVEN")
        return a, e

    for label, rows, exp_a, exp_e, exp_t, exp_ap, exp_ep in [
        ("Known",   mixed_known_rows,  52929, 874, 53803, 98.4, 1.6),
        ("Novel",   mixed_novel_rows,  10553, 147, 10700, 98.6, 1.4),
        ("R3 Only", r3_only_rows,      1120,  0,   1120,  None, None),
        ("TO",      tracker_only_rows, 11,    323, 334,   3.3,  96.7),
    ]:
        a, e = ctx(rows)
        t = a + e
        check(f"{label} auto", a, exp_a)
        check(f"{label} event", e, exp_e)
        check(f"{label} total", t, exp_t)
        if exp_ap is not None:
            check(f"{label} auto%", pct(a, t), exp_ap)
            check(f"{label} event%", pct(e, t), exp_ep)

    # Mixed total (table row)
    mx_a = sum(1 for r in mixed_rows if r["Trigger_Context"] == "AUTONOMOUS")
    mx_e = sum(1 for r in mixed_rows if r["Trigger_Context"] == "EVENT_DRIVEN")
    mx_t = mx_a + mx_e
    check("Mixed auto", mx_a, 63482)
    check("Mixed event", mx_e, 1021)
    check("Mixed total", mx_t, 64503)
    check("Mixed auto%", pct(mx_a, mx_t), 98.4)
    check("Mixed event%", pct(mx_e, mx_t), 1.6)


# ═══════════════════════════════════════════════════════════════════════
# TABLE 8: Sink distribution
# ═══════════════════════════════════════════════════════════════════════

def verify_table8():
    section("TABLE 8: Sink distribution (tab:sinks-dist)\n"
            "  createElement = createElement().href only")

    dom_iframe = dom_create = dom_image = dom_other = 0
    cookie_w = web_storage = navigation = sendbeacon = other_s = 0

    for r in mixed_rows:
        s = r["Leak_Method (Sink)"]
        if "LoadFrameInst" in s:
            dom_iframe += 1
        elif s == "createElement().href (Evasion Suspected)":
            dom_create += 1
        elif s == "Image().src (Evasion Suspected)":
            dom_image += 1
        elif "Evasion Suspected" in s:
            dom_other += 1
        elif s == "document.cookie":
            cookie_w += 1
        elif "Storage" in s:
            web_storage += 1
        elif "window.open" in s or "location." in s:
            navigation += 1
        elif "sendBeacon" in s:
            sendbeacon += 1
        else:
            other_s += 1

    dom_total = dom_iframe + dom_create + dom_image + dom_other
    mr = len(mixed_rows)

    check("DOM total", dom_total, 41287)
    check("DOM %", pct(dom_total, mr), 64.0)
    check("DOM iframe", dom_iframe, 27095)
    check("DOM iframe %", pct(dom_iframe, mr), 42.0)
    check("DOM createElement", dom_create, 6515)
    check("DOM create %", pct(dom_create, mr), 10.1)
    check("DOM image", dom_image, 1327)
    check("DOM image %", pct(dom_image, mr), 2.1)
    check("DOM other", dom_other, 6350)
    check("DOM other %", pct(dom_other, mr), 9.8)
    check("Cookie write", cookie_w, 9998)
    check("Cookie %", pct(cookie_w, mr), 15.5)
    check("Web Storage", web_storage, 6939)
    check("Storage %", pct(web_storage, mr), 10.8)
    check("Navigation", navigation, 4868)
    check("Nav %", pct(navigation, mr), 7.5)
    check("sendBeacon", sendbeacon, 1393)
    check("Beacon %", pct(sendbeacon, mr), 2.2)
    check("Other", other_s, 18)
    check("Sink total", dom_total + cookie_w + web_storage + navigation + sendbeacon + other_s, 64503)

    # ── Domain-level columns (Table 8) ──
    from collections import defaultdict as _dd
    dom_sink = _dd(set)
    for r in mixed_rows:
        s = r["Leak_Method (Sink)"]
        d = r["Domain"]
        if "LoadFrameInst" in s:
            dom_sink["iframe"].add(d)
        elif s == "createElement().href (Evasion Suspected)":
            dom_sink["create"].add(d)
        elif s == "Image().src (Evasion Suspected)":
            dom_sink["image"].add(d)
        elif "Evasion Suspected" in s:
            dom_sink["dom_other"].add(d)
        elif s == "document.cookie":
            dom_sink["cookie"].add(d)
        elif "Storage" in s:
            dom_sink["storage"].add(d)
        elif "window.open" in s or "location." in s:
            dom_sink["navigation"].add(d)
        elif "sendBeacon" in s:
            dom_sink["beacon"].add(d)
        else:
            dom_sink["other"].add(d)

    dom_dom = dom_sink["iframe"] | dom_sink["create"] | dom_sink["image"] | dom_sink["dom_other"]
    md = len(mixed_domains)
    check("DOM dom total", len(dom_dom), 12222)
    check("DOM dom total %", pct(len(dom_dom), md), 98.5)
    check("DOM dom iframe", len(dom_sink["iframe"]), 11871)
    check("DOM dom iframe %", pct(len(dom_sink["iframe"]), md), 95.7)
    check("DOM dom createElement", len(dom_sink["create"]), 6251)
    check("DOM dom create %", pct(len(dom_sink["create"]), md), 50.4)
    check("DOM dom image", len(dom_sink["image"]), 994)
    check("DOM dom image %", pct(len(dom_sink["image"]), md), 8.0)
    check("DOM dom other", len(dom_sink["dom_other"]), 3902)
    check("DOM dom other %", pct(len(dom_sink["dom_other"]), md), 31.5)
    check("Cookie dom", len(dom_sink["cookie"]), 6491)
    check("Cookie dom %", pct(len(dom_sink["cookie"]), md), 52.3)
    check("Storage dom", len(dom_sink["storage"]), 4423)
    check("Storage dom %", pct(len(dom_sink["storage"]), md), 35.7)
    check("Navigation dom", len(dom_sink["navigation"]), 3527)
    check("Navigation dom %", pct(len(dom_sink["navigation"]), md), 28.4)
    check("Beacon dom", len(dom_sink["beacon"]), 1194)
    check("Beacon dom %", pct(len(dom_sink["beacon"]), md), 9.6)


# ═══════════════════════════════════════════════════════════════════════
# TABLE 9: CNAME beneficiaries
# ═══════════════════════════════════════════════════════════════════════

def verify_table9():
    section("TABLE 9: CNAME beneficiaries (tab:cname-beneficiaries)\n"
            "  Counting: ALL route classes (Mixed + R3-only + Tracker-only)")

    cname_mixed = [r for r in mixed_rows if "CNAME" in r.get("Party_Check", "")]
    cname_all = [r for r in all_route_rows if "CNAME" in (r.get("Party_Check") or "")]
    check("CNAME routes (mixed)", len(cname_mixed), 1456)

    cname_benef = Counter()
    for r in cname_all:
        obs = r.get("Observed_Trackers") or ""
        if obs and obs != "None":
            for d in obs.split(" | "):
                d = d.strip()
                if d:
                    cname_benef[d] += 1

    for domain, exp in [
        ("www.googletagmanager.com", 1025),
        ("www.google-analytics.com", 523),
        ("static.cloudflareinsights.com", 220),
        ("bat.bing.com", 199),
        ("www.clarity.ms", 193),
        ("analytics.google.com", 148),
        ("dpm.demdex.net", 136),
    ]:
        check(domain, cname_benef.get(domain, 0), exp)

    return cname_mixed


# ═══════════════════════════════════════════════════════════════════════
# TABLE 10: CNAME examples
# ═══════════════════════════════════════════════════════════════════════

def verify_table10(cname_mixed):
    section("TABLE 10: CNAME examples (tab:cname-examples)")

    cname_by_dom = defaultdict(list)
    for r in cname_mixed:
        cname_by_dom[r["Domain"]].append(r)

    for ed, exp_dom_pct, exp_b in [
        ("statnews.com", 70.6, 14),
        ("aon.com", 66.7, 11),
        ("immersivetranslate.com", 40.0, 6),
        ("webflow.com", 83.3, 7),
        ("rtbf.be", 42.9, 3),
    ]:
        rd = cname_by_dom.get(ed, [])
        dom_d = sum(1 for r in rd if "Evasion" in r.get("Leak_Method (Sink)", ""))
        b = set()
        for r in rd:
            obs = r.get("Observed_Trackers") or ""
            if obs and obs != "None":
                for d in obs.split(" | "):
                    d = d.strip()
                    if d:
                        b.add(d)
        check(f"{ed} DOM%", pct(dom_d, len(rd)), exp_dom_pct)
        check(f"{ed} beneficiaries", len(b), exp_b)


# ═══════════════════════════════════════════════════════════════════════
# BODY TEXT: §4.3 Evasion Techniques
# ═══════════════════════════════════════════════════════════════════════

def verify_body_43(r4_total, r4_hid):
    section("BODY TEXT: §4.3 Evasion Techniques")

    check("R4 hidden % of R4", pct(r4_hid, r4_total), 94.3)

    novel_single = sum(
        1 for r in mixed_novel_rows
        if len(parse_rules_explicit(r["Threat_Type"])) == 1
    )
    check("Novel single-rule %", pct(novel_single, len(mixed_novel_rows)), 31.0)


# ═══════════════════════════════════════════════════════════════════════
# BODY TEXT: §4.5 Exfiltration Channels
# ═══════════════════════════════════════════════════════════════════════

def verify_body_45():
    section("BODY TEXT: §4.5 Exfiltration Channels")

    mr = len(mixed_rows)

    # Cookie-free domains
    domains_w_cookie = set(
        r["Domain"] for r in mixed_rows if r["Leak_Method (Sink)"] == "document.cookie"
    )
    domains_no_cookie = mixed_domains - domains_w_cookie
    check("Domains without cookie write", len(domains_no_cookie), 5912)
    check("Domains without cookie write %", pct(len(domains_no_cookie), len(mixed_domains)), 47.7)

    # Cookie-less comparison (§4.5 body text)
    nc_rows = [r for r in mixed_rows if r["Domain"] in domains_no_cookie]
    ck_rows = [r for r in mixed_rows if r["Domain"] in domains_w_cookie]
    nc_n = len(domains_no_cookie)
    ck_n = len(domains_w_cookie)

    # DOM exfiltration
    nc_dom = len(set(r["Domain"] for r in nc_rows if "Evasion" in r.get("Leak_Method (Sink)", "")))
    ck_dom = len(set(r["Domain"] for r in ck_rows if "Evasion" in r.get("Leak_Method (Sink)", "")))
    check("No-cookie DOM %", pct(nc_dom, nc_n), 98.9)
    check("Cookie DOM %", pct(ck_dom, ck_n), 98.2)

    # Date source
    nc_date = len(set(r["Domain"] for r in nc_rows if r["Leaked_Data (Source)"] in ("Date", "Date.now")))
    ck_date = len(set(r["Domain"] for r in ck_rows if r["Leaked_Data (Source)"] in ("Date", "Date.now")))
    check("No-cookie Date %", pct(nc_date, nc_n), 24.0)
    check("Cookie Date %", pct(ck_date, ck_n), 94.4)

    # 3rd-party
    nc_3p = len(set(r["Domain"] for r in nc_rows
                    if r.get("Party_Check", "").startswith("3rd-Party")
                    or r.get("Party_Check", "").startswith("Confirmed 3rd")))
    ck_3p = len(set(r["Domain"] for r in ck_rows
                    if r.get("Party_Check", "").startswith("3rd-Party")
                    or r.get("Party_Check", "").startswith("Confirmed 3rd")))
    check("No-cookie 3P %", pct(nc_3p, nc_n), 7.9)
    check("Cookie 3P %", pct(ck_3p, ck_n), 25.1)

    # Storage read → DOM (top-tier evaders)
    storage_read_srcs = {"localStorage.getItem", "sessionStorage.getItem"}
    sr_dom = [r for r in mixed_rows
              if r["Leaked_Data (Source)"] in storage_read_srcs
              and "Evasion Suspected" in r.get("Leak_Method (Sink)", "")]
    sr_dom_doms = set(r["Domain"] for r in sr_dom)
    check("Storage read→DOM domains", len(sr_dom_doms), 209)
    check("Storage read→DOM routes", len(sr_dom), 250)
    check("Storage read→DOM % of mixed", pct(len(sr_dom_doms), len(mixed_domains)), 1.7)
    sr_auto = sum(1 for r in sr_dom if "AUTONOMOUS" in r.get("Trigger_Context", ""))
    check("Storage read→DOM autonomous %", pct(sr_auto, len(sr_dom)), 98.0)
    sr_dyn = sum(1 for r in sr_dom if r["Destination"] == "DYNAMIC_URL")
    check("Storage read→DOM DYNAMIC_URL %", pct(sr_dyn, len(sr_dom)), 64.4)

    # Sources
    src = Counter(r["Leaked_Data (Source)"] for r in mixed_rows)
    loc = sum(v for k, v in src.items() if k.startswith("location."))
    obf = (src.get("Obfuscated_Property (LoadPropertyInst)", 0)
           + src.get("Obfuscated_Call (CallInst)", 0))
    date = src.get("Date", 0) + src.get("Date.now", 0)
    cookie_rd = src.get("document.cookie", 0)

    check("Location source", loc, 27469)
    check("Location %", pct(loc, mr), 42.6)
    check("Obfuscated source", obf, 18073)
    check("Obfuscated %", pct(obf, mr), 28.0)
    check("Date/timing source", date, 12855)
    check("Date %", pct(date, mr), 19.9)
    check("Cookie read", cookie_rd, 721)
    check("Cookie read %", pct(cookie_rd, mr), 1.1)

    # Source domain counts
    md = len(mixed_domains)
    src_dom = defaultdict(set)
    for r in mixed_rows:
        s = r["Leaked_Data (Source)"]
        d = r["Domain"]
        if s.startswith("location."):
            src_dom["location"].add(d)
        if "Obfuscated" in s:
            src_dom["obfuscated"].add(d)
        if s in ("Date", "Date.now"):
            src_dom["date"].add(d)
        if s == "document.cookie":
            src_dom["cookie_read"].add(d)
    check("Location source domains", len(src_dom["location"]), 11920)
    check("Obfuscated source domains", len(src_dom["obfuscated"]), 9646)
    check("Date source domains", len(src_dom["date"]), 7543)
    check("Cookie read domains", len(src_dom["cookie_read"]), 690)

    # Source-sink flow route + domain counts (broad LoadFrameInst filter)
    flow_routes = defaultdict(int)
    flow_dom = defaultdict(set)
    for r in mixed_rows:
        s = r["Leaked_Data (Source)"]
        sink = r.get("Leak_Method (Sink)", "")
        d = r["Domain"]
        if "Obfuscated" in s and "LoadFrameInst" in sink:
            flow_routes["obf_iframe"] += 1
            flow_dom["obf_iframe"].add(d)
        if s == "location.href" and "LoadFrameInst" in sink:
            flow_routes["loc_iframe"] += 1
            flow_dom["loc_iframe"].add(d)
        if s == "location.href" and "createElement" in sink:
            flow_routes["loc_create"] += 1
            flow_dom["loc_create"].add(d)
        if s in ("Date", "Date.now") and sink == "document.cookie":
            flow_routes["date_cookie"] += 1
            flow_dom["date_cookie"].add(d)
    check("Obf→iframe routes", flow_routes["obf_iframe"], 10966)
    check("Obf→iframe domains", len(flow_dom["obf_iframe"]), 9102)
    check("Loc→iframe routes", flow_routes["loc_iframe"], 6243)
    check("Loc→iframe domains", len(flow_dom["loc_iframe"]), 5844)
    check("Loc→createElement routes", flow_routes["loc_create"], 6144)
    check("Loc→createElement domains", len(flow_dom["loc_create"]), 6136)
    check("Date→cookie routes", flow_routes["date_cookie"], 5950)
    check("Date→cookie domains", len(flow_dom["date_cookie"]), 5895)


# ═══════════════════════════════════════════════════════════════════════
# BODY TEXT: §4.6 Destination Obfuscation & CNAME details
# ═══════════════════════════════════════════════════════════════════════

def verify_body_46():
    section("BODY TEXT: §4.6 Destination Obfuscation")

    mr = len(mixed_rows)

    dyn_url = sum(1 for r in mixed_rows if r.get("Destination", "") == "DYNAMIC_URL")
    check("DYNAMIC_URL routes", dyn_url, 40417)
    check("DYNAMIC_URL %", pct(dyn_url, mr), 62.7)

    # Triple-blind: obfuscated source + DYNAMIC_URL + DOM sink
    triple_blind = sum(
        1 for r in mixed_rows
        if "Obfuscated" in r["Leaked_Data (Source)"]
        and r.get("Destination", "") == "DYNAMIC_URL"
        and "Evasion" in r.get("Leak_Method (Sink)", "")
    )
    triple_blind_doms = len(set(
        r["Domain"] for r in mixed_rows
        if "Obfuscated" in r["Leaked_Data (Source)"]
        and r.get("Destination", "") == "DYNAMIC_URL"
        and "Evasion" in r.get("Leak_Method (Sink)", "")
    ))
    check("Triple-blind routes", triple_blind, 6742)
    check("Triple-blind %", pct(triple_blind, mr), 10.5)
    check("Triple-blind domains", triple_blind_doms, 4917)
    check("Triple-blind dom %", pct(triple_blind_doms, len(mixed_domains)), 39.6)

    party = Counter(r.get("Party_Check", "") for r in mixed_rows)
    third_p = sum(v for k, v in party.items()
                  if k.startswith("3rd-Party") or k.startswith("Confirmed 3rd"))
    check("3rd-party routes", third_p, 2810)
    check("3rd-party %", pct(third_p, mr), 4.4)
    check("CNAME routes", party.get("1st-Party (CNAME Cloaked)", 0), 1456)
    check("Unknown (Obfuscated) routes", party.get("Unknown (Obfuscated)", 0), 42626)
    check("Unknown (Obfuscated) %", pct(party.get("Unknown (Obfuscated)", 0), mr), 66.1)

    # Domain-level party
    md = len(mixed_domains)
    dyn_doms = len(set(r["Domain"] for r in mixed_rows
                       if r.get("Destination", "") == "DYNAMIC_URL"))
    check("DYNAMIC_URL domains", dyn_doms, 11792)
    check("DYNAMIC_URL dom %", pct(dyn_doms, md), 95.1)

    r4_hid_doms = len(set(r["Domain"] for r in mixed_rows
                          if has_r4_sink(r.get("Leak_Method (Sink)", ""))
                          and has_r4_hid(r["Threat_Type"])))
    check("R4 hidden dest domains", r4_hid_doms, 11780)

    tp_doms = len(set(r["Domain"] for r in mixed_rows
                      if r.get("Party_Check", "").startswith("3rd-Party")
                      or r.get("Party_Check", "").startswith("Confirmed 3rd")))
    check("3rd-party domains", tp_doms, 2099)

    cname_doms = len(set(r["Domain"] for r in mixed_rows
                         if "CNAME" in r.get("Party_Check", "")))
    check("CNAME domains", cname_doms, 313)

    unk_doms = len(set(r["Domain"] for r in mixed_rows
                       if r.get("Party_Check", "") == "Unknown (Obfuscated)"))
    check("Unknown party domains", unk_doms, 11877)

    # Novel trackers
    novel_dyn = sum(1 for r in mixed_novel_rows if r.get("Destination", "") == "DYNAMIC_URL")
    novel_unk = sum(1 for r in mixed_novel_rows
                    if r.get("Party_Check", "") == "Unknown (Obfuscated)")
    novel_3p = sum(1 for r in mixed_novel_rows
                   if r.get("Party_Check", "") == "3rd-Party (Identified)")
    check("Novel DYNAMIC_URL %", pct(novel_dyn, len(mixed_novel_rows)), 63.9)
    check("Novel unknown %", pct(novel_unk, len(mixed_novel_rows)), 67.2)
    check("Novel 3P routes", novel_3p, 37)
    check("Novel 3P %", pct(novel_3p, len(mixed_novel_rows)), 0.3)

    # §4.3 domain-level stats for novel trackers
    nd = len(mixed_novel_domains)
    nd_dyn_dom = len(set(r["Domain"] for r in mixed_novel_rows
                         if r.get("Destination", "") == "DYNAMIC_URL"))
    nd_unk_dom = len(set(r["Domain"] for r in mixed_novel_rows
                         if r.get("Party_Check", "") == "Unknown (Obfuscated)"))
    nd_3p_dom = len(set(r["Domain"] for r in mixed_novel_rows
                        if r.get("Party_Check", "") == "3rd-Party (Identified)"))
    nd_dom_sink = len(set(r["Domain"] for r in mixed_novel_rows
                          if "Evasion" in r.get("Leak_Method (Sink)", "")))
    check("Novel dom DYNAMIC_URL %", pct(nd_dyn_dom, nd), 93.2)
    check("Novel dom unknown party %", pct(nd_unk_dom, nd), 94.1)
    check("Novel dom 3P", nd_3p_dom, 33)
    check("Novel dom 3P %", pct(nd_3p_dom, nd), 1.4)
    check("Novel dom DOM sink %", pct(nd_dom_sink, nd), 98.2)

    # Novel single-rule domains
    from collections import defaultdict as dd
    novel_dom_rules = dd(list)
    for r in mixed_novel_rows:
        rules = set()
        for m in re.findall(r'\(Rule (\d)\)', r["Threat_Type"]):
            rules.add(f"R{m}")
        if "Fingerprinting_Leak" in r["Threat_Type"]:
            rules.add("R5")
        novel_dom_rules[r["Domain"]].append(len(rules))
    nd_single = sum(1 for d, counts in novel_dom_rules.items()
                    if all(c == 1 for c in counts))
    check("Novel dom all-single-rule %", pct(nd_single, nd), 0.7)

    # Novel per-axis obfuscation (§4.3 + §4.7)
    nr = len(mixed_novel_rows)
    novel_dom = sum(1 for r in mixed_novel_rows
                    if "Evasion" in r.get("Leak_Method (Sink)", ""))
    novel_obf = sum(1 for r in mixed_novel_rows
                    if "Obfuscated" in r["Leaked_Data (Source)"])
    novel_triple = sum(1 for r in mixed_novel_rows
                       if "Obfuscated" in r["Leaked_Data (Source)"]
                       and r.get("Destination", "") == "DYNAMIC_URL"
                       and "Evasion" in r.get("Leak_Method (Sink)", ""))
    check("Novel DOM sink %", pct(novel_dom, nr), 64.9)
    check("Novel obfuscated src %", pct(novel_obf, nr), 28.7)
    check("Novel triple-blind %", pct(novel_triple, nr), 12.9)

    # Known per-axis obfuscation (§4.3 comparison)
    kr = len(mixed_known_rows)
    known_dyn = sum(1 for r in mixed_known_rows if r.get("Destination", "") == "DYNAMIC_URL")
    known_dom = sum(1 for r in mixed_known_rows
                    if "Evasion" in r.get("Leak_Method (Sink)", ""))
    known_obf = sum(1 for r in mixed_known_rows
                    if "Obfuscated" in r["Leaked_Data (Source)"])
    check("Known DYNAMIC_URL %", pct(known_dyn, kr), 62.4)
    check("Known DOM sink %", pct(known_dom, kr), 63.8)
    check("Known obfuscated src %", pct(known_obf, kr), 27.9)

    # Per-axis domain counts (Table obfuscation-axes)
    def dom_axis(rows, cond):
        return len(set(r["Domain"] for r in rows if cond(r)))

    kd_total = len(mixed_known_domains)
    nd_total = len(mixed_novel_domains)

    kd_obf = dom_axis(mixed_known_rows, lambda r: "Obfuscated" in r["Leaked_Data (Source)"])
    nd_obf = dom_axis(mixed_novel_rows, lambda r: "Obfuscated" in r["Leaked_Data (Source)"])
    check("Known dom obf src", kd_obf, 7896)
    check("Known dom obf src %", pct(kd_obf, kd_total), 78.0)
    check("Novel dom obf src", nd_obf, 1751)
    check("Novel dom obf src %", pct(nd_obf, nd_total), 76.8)

    kd_dyn = dom_axis(mixed_known_rows, lambda r: r.get("Destination", "") == "DYNAMIC_URL")
    nd_dyn = dom_axis(mixed_novel_rows, lambda r: r.get("Destination", "") == "DYNAMIC_URL")
    check("Known dom DYNAMIC_URL", kd_dyn, 9670)
    check("Known dom DYNAMIC_URL %", pct(kd_dyn, kd_total), 95.5)
    check("Novel dom DYNAMIC_URL", nd_dyn, 2125)
    check("Novel dom DYNAMIC_URL %", pct(nd_dyn, nd_total), 93.2)

    kd_dom = dom_axis(mixed_known_rows, lambda r: "Evasion" in r.get("Leak_Method (Sink)", ""))
    nd_dom = dom_axis(mixed_novel_rows, lambda r: "Evasion" in r.get("Leak_Method (Sink)", ""))
    check("Known dom DOM sink", kd_dom, 9984)
    check("Known dom DOM sink %", pct(kd_dom, kd_total), 98.6)
    check("Novel dom DOM sink", nd_dom, 2239)
    check("Novel dom DOM sink %", pct(nd_dom, nd_total), 98.2)

    kd_tri = dom_axis(mixed_known_rows, lambda r:
        "Obfuscated" in r["Leaked_Data (Source)"]
        and r.get("Destination", "") == "DYNAMIC_URL"
        and "Evasion" in r.get("Leak_Method (Sink)", ""))
    nd_tri = dom_axis(mixed_novel_rows, lambda r:
        "Obfuscated" in r["Leaked_Data (Source)"]
        and r.get("Destination", "") == "DYNAMIC_URL"
        and "Evasion" in r.get("Leak_Method (Sink)", ""))
    check("Known dom triple", kd_tri, 3854)
    check("Known dom triple %", pct(kd_tri, kd_total), 38.1)
    check("Novel dom triple", nd_tri, 1063)
    check("Novel dom triple %", pct(nd_tri, nd_total), 46.6)

    # Confidence score validation (Appendix)
    # Use exclusive Novel set (overlap-domains counted as Known).
    domain_known_max = {}
    domain_novel_max = {}
    for r in mixed_rows:
        dom = r["Domain"]
        score = int(r["Confidence_Score"])
        if dom in mixed_known_domains:
            domain_known_max[dom] = max(domain_known_max.get(dom, 0), score)
        elif dom in mixed_novel_domains:
            domain_novel_max[dom] = max(domain_novel_max.get(dom, 0), score)

    from collections import Counter as _C
    known_dom_scores = _C(domain_known_max.values())
    novel_dom_scores = _C(domain_novel_max.values())
    kdt = sum(known_dom_scores.values())
    ndt = sum(novel_dom_scores.values())

    check("Appendix: Known domains total", kdt, 10122)
    check("Appendix: Novel domains total", ndt, 2281)
    check("Appendix: Known Score 2 domains", known_dom_scores[2], 37)
    check("Appendix: Known Score 2 %", pct(known_dom_scores[2], kdt), 0.4)
    check("Appendix: Known Score 3 domains", known_dom_scores[3], 1795)
    check("Appendix: Known Score 3 %", pct(known_dom_scores[3], kdt), 17.7)
    check("Appendix: Known Score 4 domains", known_dom_scores[4], 7870)
    check("Appendix: Known Score 4 %", pct(known_dom_scores[4], kdt), 77.8)
    check("Appendix: Known Score 5 domains", known_dom_scores[5], 420)
    check("Appendix: Known Score 5 %", pct(known_dom_scores[5], kdt), 4.1)
    k_ge4 = known_dom_scores[4] + known_dom_scores[5]
    check("Appendix: Known Score>=4 domains", k_ge4, 8290)
    check("Appendix: Known Score>=4 %", pct(k_ge4, kdt), 81.9)

    check("Appendix: Novel Score 2 domains", novel_dom_scores[2], 16)
    check("Appendix: Novel Score 2 %", pct(novel_dom_scores[2], ndt), 0.7)
    check("Appendix: Novel Score 3 domains", novel_dom_scores[3], 1749)
    check("Appendix: Novel Score 3 %", pct(novel_dom_scores[3], ndt), 76.7)
    check("Appendix: Novel Score 4 domains", novel_dom_scores[4], 451)
    check("Appendix: Novel Score 4 %", pct(novel_dom_scores[4], ndt), 19.8)
    check("Appendix: Novel Score 5 domains", novel_dom_scores[5], 65)
    check("Appendix: Novel Score 5 %", pct(novel_dom_scores[5], ndt), 2.8)
    n_ge4 = novel_dom_scores[4] + novel_dom_scores[5]
    check("Appendix: Novel Score>=4 domains", n_ge4, 516)
    check("Appendix: Novel Score>=4 %", pct(n_ge4, ndt), 22.6)

    # CNAME details
    cname_mixed = [r for r in mixed_rows if "CNAME" in r.get("Party_Check", "")]
    cn = len(cname_mixed)

    cname_dom = sum(1 for r in cname_mixed
                    if "Evasion" in r.get("Leak_Method (Sink)", ""))
    check("CNAME DOM routes", cname_dom, 1035)
    check("CNAME DOM %", pct(cname_dom, cn), 71.1)

    # CNAME+DOM confidence score
    cname_dom_rows = [r for r in cname_mixed
                      if "Evasion" in r.get("Leak_Method (Sink)", "")]
    cname_dom_scores = [float(r["Confidence_Score"]) for r in cname_dom_rows
                        if r.get("Confidence_Score")]
    cname_dom_avg = sum(cname_dom_scores) / len(cname_dom_scores)
    check("CNAME+DOM avg confidence", round(cname_dom_avg, 2), 4.90)
    cname_dom_s5 = sum(1 for s in cname_dom_scores if s >= 5)
    check("CNAME+DOM Score 5 %", pct(cname_dom_s5, len(cname_dom_scores)), 91.8)
    all_scores = [float(r["Confidence_Score"]) for r in mixed_rows
                  if r.get("Confidence_Score")]
    all_avg = sum(all_scores) / len(all_scores)
    check("All mixed avg confidence", round(all_avg, 2), 3.14)
    all_s5 = sum(1 for s in all_scores if s >= 5)
    check("All mixed Score 5 %", pct(all_s5, len(all_scores)), 1.9)

    cname_r345d = sum(
        1 for r in cname_mixed
        if has_r3(r["Threat_Type"])
        and has_r4_sink(r["Leak_Method (Sink)"])
        and "Deterministic" in r["Threat_Type"]
    )
    check("CNAME R3+R4+R5[D]", cname_r345d, 944)
    check("CNAME R3+R4+R5[D] %", pct(cname_r345d, cn), 64.8)

    cname_ifr = sum(1 for r in cname_mixed
                    if "LoadFrameInst" in r.get("Leak_Method (Sink)", ""))
    cname_cre = sum(1 for r in cname_mixed
                    if "createElement" in r.get("Leak_Method (Sink)", ""))
    cname_img = sum(1 for r in cname_mixed
                    if "Image().src" in r.get("Leak_Method (Sink)", ""))
    cname_net = sum(1 for r in cname_mixed
                    if "sendBeacon" in r.get("Leak_Method (Sink)", "")
                    or r.get("Leak_Method (Sink)", "") == "fetch")
    check("CNAME iframe", cname_ifr, 671)
    check("CNAME createElement", cname_cre, 176)
    check("CNAME image", cname_img, 33)
    check("CNAME network", cname_net, 30)

    # CNAME domain-level
    cname_dom_set = set(r["Domain"] for r in cname_mixed)
    cname_dom_evasion = set(r["Domain"] for r in cname_mixed
                           if "Evasion" in r.get("Leak_Method (Sink)", ""))
    cname_r345d_doms = set(
        r["Domain"] for r in cname_mixed
        if has_r3(r["Threat_Type"])
        and has_r4_sink(r["Leak_Method (Sink)"])
        and "Deterministic" in r["Threat_Type"]
    )
    check("CNAME total domains", len(cname_dom_set), 313)
    check("CNAME DOM domains", len(cname_dom_evasion), 308)
    check("CNAME R3+R4+R5[D] domains", len(cname_r345d_doms), 298)

    # §4.4 R3+R4+R5 combo (all three fire on same route)
    r345_routes = sum(
        1 for r in mixed_rows
        if has_r3(r["Threat_Type"])
        and has_r4_sink(r.get("Leak_Method (Sink)", ""))
        and (("Deterministic" in r["Threat_Type"] or "Probabilistic" in r["Threat_Type"])
             and ("Rule 5" in r["Threat_Type"] or "Semantic_CrossValidation" in r["Threat_Type"]))
    )
    r345_doms = len(set(
        r["Domain"] for r in mixed_rows
        if has_r3(r["Threat_Type"])
        and has_r4_sink(r.get("Leak_Method (Sink)", ""))
        and (("Deterministic" in r["Threat_Type"] or "Probabilistic" in r["Threat_Type"])
             and ("Rule 5" in r["Threat_Type"] or "Semantic_CrossValidation" in r["Threat_Type"]))
    ))
    check("R3+R4+R5 combo routes", r345_routes, 23670)
    check("R3+R4+R5 combo domains", r345_doms, 7942)

    # §4.1 all classified domains
    all_class_doms = mixed_domains | r3_only_domains | tracker_only_domains
    check("All classified domains", len(all_class_doms), 13479)


# ═══════════════════════════════════════════════════════════════════════
# TEX CROSS-CHECK: scan tex files for stale numbers
# ═══════════════════════════════════════════════════════════════════════

def tex_crosscheck():
    """Scan all tex files and verify key numbers appear correctly.

    For each computed value, we define the expected tex string that should
    appear.  If a WRONG version of the string exists, we flag it.
    """
    print(f"\n{'=' * 70}")
    print("TEX CROSS-CHECK: scanning *.tex for stale numbers")
    print("=" * 70)

    # Load all tex content
    tex_files = {}
    for path in sorted(globmod.glob(os.path.join(SCRIPT_DIR, "*.tex"))):
        with open(path, "r", encoding="utf-8") as f:
            tex_files[os.path.basename(path)] = f.read()

    # Define (correct_regex, wrong_regex_list, description) triples.
    # Regex patterns use (?<!\d) / (?!\d) word boundaries so e.g. "4.3"
    # doesn't false-match inside "94.3".
    def nb(s):
        """Wrap a number string with non-digit boundaries for regex."""
        return r'(?<!\d)' + re.escape(s) + r'(?!\d)'

    checks = [
        # Destination obfuscation %
        (nb("62.7"), [nb("62.6")], "DYNAMIC_URL destination obfuscation %"),
        # 3rd-party %
        (nb("4.4"),  [nb("4.3")],  "3rd-party route %", r"Novel|EasyPrivacy|absent"),
        # Novel unknown party %
        (nb("67.2"), [nb("67.1")], "Novel unknown party %"),
        # Novel single-rule %
        (nb("84.6"), [nb("84.5")], "Novel single-rule %"),
        # R4 hidden %
        (nb("94.3"), [nb("94.4")], "R4 hidden % of R4", r"Date|cookie"),
        # CNAME DOM %
        (nb("71.1"), [nb("70.2")], "CNAME DOM-mediated %"),
        # CNAME R3+R4+R5[D] %
        (nb("64.8"), [nb("58.5")], "CNAME R3+R4+R5[D] %"),
        # Table 6 absolute values
        (nb("2,370"),  [nb("2,300")],  "R4 dest identified (Table 6)"),
        (nb("38,917"), [nb("38,922"), nb("38,992")], "R4 dest hidden (Table 6)"),
        (nb("26,305"), [nb("26,340")], "R5 total (Table 6)"),
        (nb("1,600"),  [nb("1,604")],  "R5 deterministic (Table 6)"),
        (nb("24,765"), [nb("24,796")], "R5 probabilistic (Table 6)"),
        (nb("1,114"),  [nb("1,121")],  "R5 device leak (Table 6)"),
        (nb("5,080"),  [nb("5,082")],  "R2 routes (Table 6)"),
        (nb("1,498"),  [nb("1,500")],  "R1 routes (Table 6)"),
        # Body text absolutes
        (nb("2,810"),  [nb("2,801")],  "3rd-party routes"),
        (nb("1,035"),  [nb("1,023")],  "CNAME DOM routes"),
        (nb("944"),    [nb("852")],    "CNAME R3+R4+R5[D] routes"),
        # Fixed stale numbers
        (nb("42,631"), [nb("42,534")], "Unknown (Obfuscated) routes"),
        (nb("66.1"),   [nb("65.9")],   "Unknown (Obfuscated) %"),
        (nb("23,670"), [nb("14,062")], "R3+R4+R5 combo routes"),
        # Appendix: confidence score validation
        (nb("81.9"), [nb("81.8"), nb("82.0")], "Known Score>=4 %"),
        (nb("22.6"), [nb("22.5"), nb("22.7")], "Novel Score>=4 %"),
        # Source-sink flow (§4.5) — stale values from earlier version
        (nb("10,966"), [nb("10,967"), nb("8,767")],  "Obf→iframe routes"),
        (nb("6,243"),  [nb("6,244"), nb("5,428")],   "Loc→iframe routes"),
        (nb("6,144"),  [nb("6,145"), nb("6,121")],   "Loc→createElement routes"),
        (nb("5,950"),  [nb("6,466")],  "Date→cookie routes"),
    ]

    tex_issues = 0
    for check_tuple in checks:
        correct_re, wrong_res, desc = check_tuple[0], check_tuple[1], check_tuple[2]
        exclude_re = check_tuple[3] if len(check_tuple) > 3 else None
        for wrong_re in wrong_res:
            for fname, content in tex_files.items():
                has_wrong = bool(re.search(wrong_re, content))
                has_correct = bool(re.search(correct_re, content))
                if has_wrong and not has_correct:
                    print(f"  STALE  {fname}: has wrong value, missing correct  ({desc})")
                    tex_issues += 1
                elif has_wrong and has_correct:
                    # Both present — find stale lines (skip comments)
                    stale_lines = []
                    for i, line in enumerate(content.splitlines(), 1):
                        stripped = line.lstrip()
                        if not stripped.startswith("%") and re.search(wrong_re, line):
                            if exclude_re and re.search(exclude_re, line, re.IGNORECASE):
                                continue  # different statistic, not stale
                            stale_lines.append(i)
                    if stale_lines:
                        print(f"  WARN   {fname}: stale value on line(s) {stale_lines}  ({desc})")
                        tex_issues += 1

    # Also check that correct values ARE present somewhere in 04-results.tex
    required_in_04 = [
        ("62.7",   "DYNAMIC_URL %"),
        ("2,370",  "R4 dest identified"),
        ("38,917", "R4 dest hidden"),
        ("26,305", "R5 total"),
        ("5,080",  "R2 routes"),
        ("1,498",  "R1 routes"),
        ("2,810",  "3rd-party routes"),
        ("1,035",  "CNAME DOM routes"),
        ("10,966", "Obf→iframe routes"),
        ("6,243",  "Loc→iframe routes"),
        ("6,144",  "Loc→createElement routes"),
        ("5,950",  "Date→cookie routes"),
    ]
    content_04 = tex_files.get("04-results.tex", "")
    for val, desc in required_in_04:
        if not re.search(nb(val), content_04):
            print(f"  MISSING  04-results.tex: '{val}' not found  ({desc})")
            tex_issues += 1

    if tex_issues == 0:
        print("  All tex cross-checks passed.")
    else:
        print(f"\n  {tex_issues} tex issue(s) found.")

    return tex_issues


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════

def main():
    # Run all table verifications
    verify_table3()
    verify_table4()
    verify_routes_per_domain()
    verify_table5()
    r4_total, r4_hid = verify_table6()
    verify_table7()
    verify_table8()
    cname_mixed = verify_table9()
    verify_table10(cname_mixed)
    verify_body_43(r4_total, r4_hid)
    verify_body_45()
    verify_body_46()

    # Summary
    tex_issues = 0
    if MODE_TEX:
        tex_issues = tex_crosscheck()

    print(f"\n{'=' * 70}")
    print(f"SUMMARY:  {pass_count} passed,  {fail_count} failed")
    if MODE_TEX:
        print(f"TEX:      {tex_issues} issue(s)")
    print("=" * 70)

    if fail_count == 0 and tex_issues == 0:
        print("\n  ALL CHECKS PASSED")
        sys.exit(0)
    else:
        if fail_count > 0:
            print(f"\n  {fail_count} CSV-PAPER MISMATCH(ES)")
        if tex_issues > 0:
            print(f" {tex_issues} TEX ISSUE(S)")
        sys.exit(1)


if __name__ == "__main__":
    main()
