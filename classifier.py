import os
import json
import csv
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

# ==========================================
# ⚙️ 경로 세팅
# ==========================================
RESULT_DIR = os.path.expanduser("~/mixed-hermes/pipeline_results")

def _resolve_csv_path():
    """Generate a non-colliding timestamped CSV filename inside reports/."""
    base_dir = os.path.expanduser("~/mixed-hermes/csv_reports")
    os.makedirs(base_dir, exist_ok=True)          # auto-create folder
    date_str = datetime.now().strftime("%Y%m%d")
    base_name = f"malicious_domains_{date_str}"
    candidate = os.path.join(base_dir, f"{base_name}.csv")
    counter = 2
    while os.path.exists(candidate):
        candidate = os.path.join(base_dir, f"{base_name}_{counter}.csv")
        counter += 1
    return candidate

CSV_OUTPUT = _resolve_csv_path()

# ==========================================
# 🛡️ 화이트리스트 및 트래커 블랙리스트 키워드
# ==========================================
WHITELIST_KEYWORDS = [
    "login", "signin", "redirect", "sso", "oauth", 
    "auth", "verify", "returnurl", "logout"
]

TRACKER_KEYWORDS = [
    # 일반적인 행위 및 로깅 키워드
    "collect", "track", "pixel", "log", "event", "beacon", "metric", "analytics", "ads", "stats",
    "telemetry", "monitor", "insight", "impress", "measure", "ping", "push", "report", "trace", "pulse", "record",
    # 고도화된 타사 추적자 및 광고 플랫폼 전용 도메인 키워드
    "googletagmanager", "google-analytics", "doubleclick", "criteo", "hotjar", "crazyegg", 
    "mixpanel", "segment", "appdynamics", "newrelic", "sentry", "datadog", "facebook"
]

# ==========================================
# 📊 통계 변수
# ==========================================
stats = {
    "total_scanned": 0,
    "total_malicious": 0,
    "evasion_dom": 0,
    "evasion_dynamic": 0,
    "fingerprinting": 0,
    "camouflaged_3rd_party": 0,
    "dual_context": 0,        # Rule 3: AUTONOMOUS exfiltration
    "isolated_exfil": 0,      # Rule 1: physically isolated WCC exfiltration
    "parasitic_branch": 0,    # Rule 2: same source -> render + exfil simultaneously
    "semantic_crossval": 0    # Rule 5: destination reputation + source sensitivity
}

malicious_records = []

# ==========================================
# 🔍 Rule 1: WCC Physical Isolation Detector
# ==========================================
# Sink types that are purely for rendering (non-malicious by themselves)
RENDER_SINKS = {"innerHTML", "textContent", "innerText", "outerHTML",
                "insertAdjacentHTML", "value", "document.write"}

def detect_isolated_exfil(domain_name, routes):
    """
    Rule 1 (Physical Disconnection — Method A):
    A route is considered physically isolated from the UI layer if its
    path_nodes contain NO UI-indicator instructions:
      - StoreFrameInst : stores into a JS closure/frame (UI state interaction)
      - PhiInst        : merges values from conditional UI branches
      - LoadFrameInst  : loads from a JS closure/frame (UI data read)

    Pure chains of CallInst / LoadPropertyInst / BinaryOperatorInst indicate
    background SDK-style code that never touches the rendering layer —
    i.e., structurally disconnected from normal UI execution.
    """
    # Nodes that indicate interaction with the UI / DOM frame layer
    UI_INDICATOR_NODES = {"StoreFrameInst", "PhiInst", "LoadFrameInst"}

    isolated_routes = []
    for r in routes:
        path_nodes = r.get("path_nodes", [])
        sink_type  = r.get("sink_type", "")

        # Only flag Network/Navigation sinks (actual exfiltration)
        if sink_type not in {"Network", "Navigation"}:
            continue

        # If the entire path has ZERO UI-indicator nodes → physically isolated
        has_ui_node = any(node in UI_INDICATOR_NODES for node in path_nodes)
        if not has_ui_node and path_nodes:  # path must be non-empty
            isolated_routes.append(r)

    return isolated_routes


# ==========================================
# 🔍 Rule 2: Parasitic Branch Detector
# ==========================================
def detect_parasitic_branch(domain_name, routes):
    """
    Rule 2 (Parasitic Branch):
    Same Source feeds BOTH a rendering sink (normal UI) AND a
    Network/Navigation sink (exfiltration) at the same time.
    This is the classic 'parasite' pattern — piggybacks on legitimate data flow.
    """
    # Group routes by source
    source_groups = {}
    for r in routes:
        src = r.get("source_name", "") or "[Dynamic_Source]"
        source_groups.setdefault(src, []).append(r)

    parasitic = []
    for src, src_routes in source_groups.items():
        sink_types  = {r.get("sink_type", "") for r in src_routes}
        sink_names  = [r.get("sink_name", "") for r in src_routes]

        # Has both rendering (Render) and network/navigation sinks
        has_render_sink = any(
            any(rs in sn for rs in RENDER_SINKS) for sn in sink_names
        ) or "Render" in sink_types
        has_net_sink = sink_types & {"Network", "Navigation"}

        if has_render_sink and has_net_sink:
            # Only flag the network/navigation routes (the parasitic part)
            for r in src_routes:
                if r.get("sink_type", "") in {"Network", "Navigation"}:
                    parasitic.append(r)
    return parasitic

# ==========================================
# 🔍 Rule 3: Dual Execution Context Detector (domain-level)
# ==========================================
def detect_dual_context(domain_name, routes):
    """
    Rule 3 (Context Duality — domain-level):
    The domain's script simultaneously contains:
      - EVENT_DRIVEN routes: legitimate code triggered by user interaction
      - AUTONOMOUS routes : tracking code that self-executes silently

    When both co-exist, every AUTONOMOUS network/navigation/storage route
    is evidence of dual execution context — the hallmark of covert tracking.
    """
    trigger_contexts = {r.get("trigger_context", "UNKNOWN") for r in routes}

    # Duality requires BOTH contexts present in the same domain
    has_event_driven = "EVENT_DRIVEN" in trigger_contexts
    has_autonomous   = "AUTONOMOUS"   in trigger_contexts

    if not (has_event_driven and has_autonomous):
        return []  # No duality — skip

    # Flag all AUTONOMOUS routes reaching exfiltration sinks
    dual_routes = []
    for r in routes:
        if (r.get("trigger_context") == "AUTONOMOUS" and
                r.get("sink_type", "") in {"Network", "Navigation", "Storage"}):
            dual_routes.append(r)
    return dual_routes


# ==========================================
# 🔍 Rule 5: Semantic Cross-Validation Detector (domain-level)
# ==========================================
# Sensitive source types that raise the risk level
SENSITIVE_SOURCES = {
    "location.href", "location.hostname", "location.origin", "location.pathname",
    "document.URL", "document.cookie",
    "screen.width", "screen.height", "screen.colorDepth",
    "navigator.userAgent", "navigator.language", "navigator.platform",
    # Timing & session fingerprinting sources
    "Date", "performance.now", "Math.random"
}

def detect_semantic_validation(domain_name, routes, network_url_list):
    """
    Rule 5 (Semantic Cross-Validation):
    Combines destination reputation with leaked data sensitivity to confirm
    covert tracking. A route is confirmed as semantically malicious when:
      - Destination contains a known tracker keyword (reputation check)
      - AND the source is sensitive user data (sensitivity check)
    This separates legitimate telemetry (non-sensitive + 1st-party)
    from covert surveillance (sensitive data -> 3rd-party tracker).
    """
    confirmed = []
    for r in routes:
        dest_url    = r.get("destination_url", "")
        source_name = r.get("source_name", "") or ""
        sink_type   = r.get("sink_type", "")

        # Only check routes that actually exfiltrate data externally
        if sink_type not in {"Network", "Navigation"}:
            continue

        # Reputation check: destination must match a known tracker keyword
        dest_lower = dest_url.lower()
        is_tracker_dest = any(kw in dest_lower for kw in TRACKER_KEYWORDS)
        if not is_tracker_dest:
            continue

        # Sensitivity check: source must be sensitive user data
        is_sensitive_src = any(s in source_name for s in SENSITIVE_SOURCES)
        if not is_sensitive_src:
            continue

        confirmed.append(r)
    return confirmed


# ==========================================
# 🔍 1st-party(자사) vs 3rd-party(타사) 판별 함수
# ==========================================
def is_first_party(source_domain, dest_url):
    """
    source_domain: 현재 분석 중인 사이트 (예: nexon.com)
    dest_url: 데이터가 날아가는 목적지 URL (예: nxlogin.nexon.com/...)
    """
    if dest_url == "DYNAMIC_URL" or not dest_url.startswith("http"):
        return False # 난독화되었거나 완벽한 URL 형태가 아니면 일단 보수적으로 타사(의심) 취급

    try:
        # 목적지 URL에서 도메인 부분만 쏙 뽑아냅니다. (예: nxlogin.nexon.com)
        parsed_uri = urlparse(dest_url)
        dest_netloc = parsed_uri.netloc.lower()
        
        # 'www.' 같은 껍데기를 떼고 핵심 도메인만 비교합니다.
        base_source = source_domain.replace("www.", "").lower()
        
        # 목적지 도메인이 원래 도메인으로 끝나면 자사(1st-party)로 인정!
        if dest_netloc.endswith(base_source):
            return True
        return False
    except:
        return False

# ==========================================
# 🔍 Unknown 소스 휴리스틱 추론기
# ==========================================
def infer_unknown_source(route: dict) -> str:
    """
    source_name이 비어있을 때 sink/path 정보로 소스를 휴리스틱 추론.

    원인: Hephaistos C++ 엔진은 2-hop(LoadPropertyInst → StorePropertyInst)처럼
    매우 짧은 indirect property chain에서 원본 소스를 역추적하지 못함.
    (e.g.  obj.prop → frame.href  로 바로 넘어가는 패턴)

    규칙:
      1. LoadFrameInst sink → 프레임 속성을 간접 읽어 전달 (DOM Indirect Read)
      2. createElement sink → 동적 생성 엘리먼트 속성 (Dynamic Element)
      3. window.open / location.href + 2-hop → 최소 chain indirect navigation
      4. document.cookie / sessionStorage sink → 세션/쿠키 write (출처 미상)
      5. 그 외 기본 → Generic Indirect Property
    """
    sink    = route.get("sink_name", "")
    nodes   = route.get("path_nodes", [])
    plen    = route.get("path_length", 0)

    if "LoadFrameInst" in sink:
        return "Inferred: Indirect Frame Property (DOM Obfuscated)"
    if "createElement" in sink:
        return "Inferred: Dynamic Element Property"
    if sink in {"document.cookie"}:
        return "Inferred: Opaque Cookie Source"
    if sink in {"sessionStorage.setItem"}:
        return "Inferred: Opaque Storage Source"
    if plen <= 2 and set(nodes) <= {"LoadPropertyInst", "StorePropertyInst", "CallInst"}:
        return "Inferred: Indirect Prop Access (2-hop)"
    return "Inferred: Unresolved Source (Engine Limit)"

# ==========================================
# 🔍 개별 파일 분석 함수
# ==========================================
def analyze_json(file_path, draw_graphs=False):
    global stats, malicious_records

    domain_name = file_path.name.replace("_report.json", "").replace("_log.json", "").replace(".json", "")
    
    # 🌟 [하이브리드 교차검증] 크롤러가 수집해 둔 실제 네트워크 로그 불러오기
    base_dir = file_path.parent.parent
    network_log_file = base_dir / "crawler" / "collected_scripts" / domain_name / "network_logs.json"
    
    network_url_list = []
    if network_log_file.exists():
        try:
            with open(network_log_file, 'r', encoding='utf-8') as nlf:
                network_url_list = json.load(nlf)
        except:
            pass
    
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return

    is_malicious = False
    domain_threats = []

    routes = data.get("s2s_routes", [])
    for route in routes:
        sink_name = route.get("sink_name", "")
        sink_type = route.get("sink_type", "")
        source_name = route.get("source_name", "") or ""
        dest_url = route.get("destination_url", "")

        # 🔍 Unknown 소스 휴리스틱 추론: 엔진이 소스를 못 잡은 경우 레이블 부여
        if not source_name.strip():
            source_name = infer_unknown_source(route)
            route["source_name"] = source_name  # downstream Rule 함수도 동일 값 사용

        threat_type = None
        trigger_context = route.get("trigger_context", "UNKNOWN")

        # 🌟 [통합 하이브리드 수색 알고리즘]
        predicted_url = None
        is_hybrid_eligible = ("{VAR}" in dest_url)

        # 1. 완벽한 조각 맞추기 (Hybrid Reconstruction)
        if is_hybrid_eligible:
            static_fragments = [frag for frag in dest_url.split("{VAR}") if frag.strip()]
            if static_fragments: # 조각 단서가 1개라도 있는 경우에만
                for real_url in network_url_list:
                    if all(frag in real_url for frag in static_fragments):
                        predicted_url = real_url + " (🌟 Hybrid Reconstructed)"
                        break

        # 2. 명탐정 휴리스틱 예측 (Fallback)
        # - 애초에 단서가 0개 였던 경우 (DYNAMIC_URL 또는 {VAR}{VAR})
        # - 조각 단서는 있었지만({VAR}&src=js), 실제 로그에서 수학적으로 일치하는 주소를 못 찾아서 복원이 실패한 경우
        if not predicted_url and (dest_url == "DYNAMIC_URL" or is_hybrid_eligible):
            # 1순위: 명백한 3rd-party 타사 스캔 (False Positive 방지)
            for real_url in network_url_list:
                if not is_first_party(domain_name, real_url):
                    if any(t_key in real_url.lower() for t_key in TRACKER_KEYWORDS):
                        predicted_url = real_url + " (🌟 Predicted 3rd-Party Tracker)"
                        break
            
            # 2순위: 외부 추적자가 전혀 발견되지 않았을 경우, 1st-party(CNAME Cloaking) 스캔
            if not predicted_url:
                for real_url in network_url_list:
                    if is_first_party(domain_name, real_url):
                        if any(t_key in real_url.lower() for t_key in TRACKER_KEYWORDS):
                            predicted_url = real_url + " (🌟 Predicted 1st-Party Target / CNAME Cloaked)"
                            break
                            
        if predicted_url:
            dest_url = predicted_url
            route["destination_url"] = dest_url  # persist resolved URL for Rule 1/2 domain-level analysis

        # 🌟 1st-party 여부와 화이트리스트 키워드 포함 여부를 동시에 검사
        first_party = is_first_party(domain_name, dest_url)
        dest_url_lower = dest_url.lower()
        has_whitelist_keyword = any(keyword in dest_url_lower for keyword in WHITELIST_KEYWORDS)

        # 🌟 Party Check 동적 확정 로직 (논문용 세밀화)
        if "Predicted 1st-Party" in dest_url:
            party_check = "1st-Party (CNAME Cloaked)"
        elif "Predicted 3rd-Party" in dest_url or "Hybrid Reconstructed" in dest_url:
            party_check = "3rd-Party (Identified)"
        elif dest_url == "DYNAMIC_URL":
            party_check = "Unknown (Obfuscated)"
        else:
            party_check = "1st-Party" if first_party else "3rd-Party/Unknown"

        # ── Collect all independent rule matches for this route ──
        active_rules = []  # list of (threat_type, party_check) tuples

        # [Rule 4] DOM Evasion — img.src / frame.href bypass
        if "(Evasion Suspected)" in sink_name:
            if has_whitelist_keyword and first_party:
                pass  # 🟢 Whitelist: legitimate 1st-party login — skip entirely
            elif has_whitelist_keyword and not first_party:
                active_rules.append(("Evasion_with_Camouflage (Disguised Tracker)", party_check))
                stats["camouflaged_3rd_party"] += 1
                stats["evasion_dom"] += 1
            else:
                label = "DOM_Evasion (Dynamic Obfuscated)" if dest_url == "DYNAMIC_URL" else "DOM_Evasion (Rule 4)"
                active_rules.append((label, party_check))
                stats["evasion_dom"] += 1

        # [Fingerprinting] Device fingerprint data leaked to network — Rule 5 sub-case
        if ("screen" in source_name or "navigator" in source_name) and sink_type in ["Network", "Navigation"]:
            active_rules.append(("Fingerprinting_Leak (Rule 5)", party_check))
            stats["fingerprinting"] += 1

        # NOTE: Rule 3 (Dual Execution Context) is handled at domain level
        #       by detect_dual_context() below — not here.

        # Append one row per matched rule (order-independent, fully parallel)
        for threat_type, p_check in active_rules:
            is_malicious = True
            domain_threats.append({
                "Domain": domain_name,
                "Threat_Type": threat_type,
                "Trigger_Context": trigger_context,
                "Leaked_Data (Source)": source_name if source_name else "Unknown",
                "Leak_Method (Sink)": sink_name,
                "Destination": dest_url,
                "Party_Check": p_check
            })

    if is_malicious:
        stats["total_malicious"] += 1
        malicious_records.extend(domain_threats)

        # ── Rule 1: WCC isolation check ──
        isolated = detect_isolated_exfil(domain_name, routes)
        for r in isolated:
            src       = r.get("source_name", "") or "Unknown"
            sink_name = r.get("sink_name", "")
            dest_url  = r.get("destination_url", "DYNAMIC_URL")
            tctx      = r.get("trigger_context", "UNKNOWN")
            already_flagged = any(
                rec["Leaked_Data (Source)"] == src and rec["Leak_Method (Sink)"] == sink_name
                for rec in domain_threats
            )
            if not already_flagged:
                stats["isolated_exfil"] += 1
                malicious_records.append({
                    "Domain": domain_name,
                    "Threat_Type": "Isolated_Exfiltration (Rule 1)",
                    "Trigger_Context": tctx,
                    "Leaked_Data (Source)": src,
                    "Leak_Method (Sink)": sink_name,
                    "Destination": dest_url,
                    "Party_Check": "Unknown (WCC Isolated)"
                })

        # ── Rule 2: Parasitic branch check ──
        parasitic = detect_parasitic_branch(domain_name, routes)
        for r in parasitic:
            src       = r.get("source_name", "") or "Unknown"
            sink_name = r.get("sink_name", "")
            dest_url  = r.get("destination_url", "DYNAMIC_URL")
            tctx      = r.get("trigger_context", "UNKNOWN")
            stats["parasitic_branch"] += 1
            malicious_records.append({
                "Domain": domain_name,
                "Threat_Type": "Parasitic_Branch (Rule 2)",
                "Trigger_Context": tctx,
                "Leaked_Data (Source)": src,
                "Leak_Method (Sink)": sink_name,
                "Destination": dest_url,
                "Party_Check": "3rd-Party (Parasitic)"
            })

        # ── Rule 3: Domain-level dual execution context ──
        dual = detect_dual_context(domain_name, routes)
        for r in dual:
            src       = r.get("source_name", "") or "Unknown"
            sink_name = r.get("sink_name", "")
            dest_url  = r.get("destination_url", "DYNAMIC_URL")
            # Rule 3 is a domain-level structural property:
            # record every AUTONOMOUS route as evidence of duality,
            # even if also captured by Rule 4 (they are different threat dimensions)
            stats["dual_context"] += 1
            malicious_records.append({
                "Domain": domain_name,
                "Threat_Type": "Dual_Execution_Context (Rule 3)",
                "Trigger_Context": "AUTONOMOUS",
                "Leaked_Data (Source)": src,
                "Leak_Method (Sink)": sink_name,
                "Destination": dest_url,
                "Party_Check": "3rd-Party (Identified)" if "Predicted 3rd-Party" in dest_url or "Hybrid Reconstructed" in dest_url else "Unknown (Obfuscated)"
            })

        # ── Rule 5: Semantic Cross-Validation ──
        semantic = detect_semantic_validation(domain_name, routes, network_url_list)
        for r in semantic:
            src       = r.get("source_name", "") or "Unknown"
            sink_name = r.get("sink_name", "")
            dest_url  = r.get("destination_url", "DYNAMIC_URL")
            tctx      = r.get("trigger_context", "UNKNOWN")
            stats["semantic_crossval"] += 1
            malicious_records.append({
                "Domain": domain_name,
                "Threat_Type": "Semantic_CrossValidation (Rule 5)",
                "Trigger_Context": tctx,
                "Leaked_Data (Source)": src,
                "Leak_Method (Sink)": sink_name,
                "Destination": dest_url,
                "Party_Check": "Confirmed 3rd-Party Tracker (Semantic)"
            })

        
        # 🎨 [Graph Integration] If flagged malicious and --draw-graphs is set, render GTG + CTG
        if draw_graphs:
            print(f"    [🎨 Graphviz] Malicious domain visualization triggered: {domain_name}")
            viz_script = os.path.expanduser("~/mixed-hermes/build/bin/report/viz_tool7.py")
            try:
                subprocess.run(["python3", viz_script, str(file_path)], check=True)

                graph_dir = os.path.join(RESULT_DIR, "graphs")
                os.makedirs(graph_dir, exist_ok=True)

                # Render both GTG and CTG dot files into PNGs
                for graph_type in ["gtg", "ctg"]:
                    dot_file = str(file_path).replace(".json", f"_{graph_type}.dot")
                    png_file = os.path.join(graph_dir, f"{domain_name}_{graph_type}.png")
                    if os.path.exists(dot_file):
                        subprocess.run(["dot", "-Tpng", dot_file, "-o", png_file], check=True)
                        os.remove(dot_file)
                        print(f"    [🌟 Graph Saved] [{graph_type.upper()}] -> {png_file}")
            except Exception as e:
                print(f"    [❌ Graph Error] Visualization failed: {e}")

# ==========================================
# 🚀 실행부
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hephaistos V2 Intelligent Classifier")
    parser.add_argument("--draw-graphs", action="store_true", help="Automatically generate GTG/CTG graph images for malicious domains")
    args = parser.parse_args()

    print("==================================================")
    print("⚖️ Hephaistos V2 Intelligent Classifier Started...")
    print("==================================================")

    target_dir = Path(RESULT_DIR)
    json_files = list(target_dir.glob("*.json"))
    
    stats["total_scanned"] = len(json_files)
    
    for js_file in json_files:
        analyze_json(js_file, draw_graphs=args.draw_graphs)

    # 결과를 CSV로 예쁘게 저장 (중복 제거 후 Rule 번호 순 정렬 + 최종 통계 첨부)
    if malicious_records:
        RULE_ORDER = {
            "Isolated_Exfiltration (Rule 1)":              1,
            "Parasitic_Branch (Rule 2)":                   2,
            "Dual_Execution_Context (Rule 3)":             3,
            "DOM_Evasion (Rule 4)":                        4,
            "DOM_Evasion (Dynamic Obfuscated)":            4,
            "Evasion_with_Camouflage (Disguised Tracker)": 4,
            "Semantic_CrossValidation (Rule 5)":           5,
            "Fingerprinting_Leak (Rule 5)":                5,
        }

        # ── Deduplication ──────────────────────────────────────────────────
        # Group records by (Domain, Source, Sink, Destination).
        # When multiple rules fire on the same taint route, merge them into
        # one row with combined Threat_Type labels instead of separate rows.
        dedup: dict = {}  # key -> merged record
        for rec in malicious_records:
            key = (
                rec.get("Domain", ""),
                rec.get("Leaked_Data (Source)", ""),
                rec.get("Leak_Method (Sink)", ""),
                rec.get("Destination", ""),
            )
            threat = rec.get("Threat_Type", "")
            if key not in dedup:
                dedup[key] = dict(rec)  # first match becomes the base row
            else:
                existing = dedup[key]["Threat_Type"]
                if threat not in existing:           # avoid duplicate labels
                    dedup[key]["Threat_Type"] = existing + " | " + threat

        deduped = list(dedup.values())

        # Sort deduplicated rows by lowest rule number present, then domain
        def sort_key(rec):
            labels = rec.get("Threat_Type", "").split(" | ")
            min_rule = min(RULE_ORDER.get(lbl, 99) for lbl in labels)
            return (min_rule, rec.get("Domain", ""))

        deduped.sort(key=sort_key)

        # ── Post-dedup Party_Check refinement ──────────────────────────────
        # Rule 1 hardcodes Party_Check as "Unknown (WCC Isolated)" at append time.
        # After merging, if the same row also carries Rule 5 (semantic confirmation)
        # or a Predicted/Hybrid 3rd-party destination, the party is no longer unknown.
        for rec in deduped:
            threat = rec.get("Threat_Type", "")
            dest   = rec.get("Destination", "")
            if ("Isolated_Exfiltration (Rule 1)" in threat and
                    rec.get("Party_Check") == "Unknown (WCC Isolated)"):
                if ("Semantic_CrossValidation (Rule 5)" in threat or
                        "Predicted 3rd-Party" in dest or
                        "Hybrid Reconstructed" in dest):
                    rec["Party_Check"] = "3rd-Party (WCC Isolated)"

        # ── Recompute stats from deduped results ───────────────────────────
        # Pre-dedup stats[] are inflated (counted per raw append).
        # Re-derive accurate counts from the final merged rows.
        final_stats = {
            "total_scanned":       stats["total_scanned"],
            "total_malicious":     len({rec["Domain"] for rec in deduped}),
            "isolated_exfil":      0,
            "parasitic_branch":    0,
            "dual_context":        0,
            "evasion_dom":         0,
            "fingerprinting":      0,
            "semantic_crossval":   0,
            "camouflaged_3rd_party": 0,
        }
        LABEL_TO_STAT = {
            "Isolated_Exfiltration (Rule 1)":              "isolated_exfil",
            "Parasitic_Branch (Rule 2)":                   "parasitic_branch",
            "Dual_Execution_Context (Rule 3)":             "dual_context",
            "DOM_Evasion (Rule 4)":                        "evasion_dom",
            "DOM_Evasion (Dynamic Obfuscated)":            "evasion_dom",
            "Evasion_with_Camouflage (Disguised Tracker)": "camouflaged_3rd_party",
            "Semantic_CrossValidation (Rule 5)":           "semantic_crossval",
            "Fingerprinting_Leak (Rule 5)":                "fingerprinting",
        }
        for rec in deduped:
            seen_stats = set()  # avoid double-counting same stat key per row
            for label in rec.get("Threat_Type", "").split(" | "):
                label = label.strip()
                stat_key = LABEL_TO_STAT.get(label)
                if stat_key and stat_key not in seen_stats:
                    final_stats[stat_key] += 1
                    seen_stats.add(stat_key)
                # Evasion_with_Camouflage also counts toward evasion_dom
                if label == "Evasion_with_Camouflage (Disguised Tracker)" and "evasion_dom" not in seen_stats:
                    final_stats["evasion_dom"] += 1
                    seen_stats.add("evasion_dom")

        keys = deduped[0].keys()
        with open(CSV_OUTPUT, 'w', newline='', encoding='utf-8-sig') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(deduped)
            
            # 통계 블록 추가
            writer = csv.writer(output_file)
            writer.writerow([])
            writer.writerow([])
            writer.writerow(["=== Final Statistical Report ==="])
            writer.writerow(["Total domains scanned", f"{final_stats['total_scanned']}"])
            writer.writerow(["Malicious tracker infected domains", f"{final_stats['total_malicious']}"])
            writer.writerow([])
            writer.writerow(["[Detailed Evasion Technique Statistics]"])
            writer.writerow(["Isolated Exfiltration (Rule 1)",           f"{final_stats['isolated_exfil']} cases"])
            writer.writerow(["Parasitic Branch (Rule 2)",                f"{final_stats['parasitic_branch']} cases"])
            writer.writerow(["Dual Execution Context (Rule 3)",          f"{final_stats['dual_context']} cases"])
            writer.writerow(["DOM Evasion (Rule 4)",                     f"{final_stats['evasion_dom']} cases"])
            writer.writerow(["Semantic Cross-Validation (Rule 5)",       f"{final_stats['semantic_crossval']} cases"])
            writer.writerow(["  └ Fingerprinting Leak (Rule 5 sub-case)", f"{final_stats['fingerprinting']} cases"])
            writer.writerow(["Camouflaged 3rd-party leak",                f"{final_stats['camouflaged_3rd_party']} cases (Core finding!)"])

    # final_stats is available only if malicious_records existed; fall back to raw stats otherwise
    _s = final_stats if malicious_records else stats
    print("✅ Analysis Complete! [Final Statistical Report]")
    print(f"- Total domains scanned : {_s['total_scanned']}")
    print(f"- 🚨 Malicious tracker infected domains : {_s['total_malicious']}\n")
    print("[Detailed Evasion Technique Statistics]")
    print(f"  > Isolated Exfiltration (Rule 1)        : {_s['isolated_exfil']} cases")
    print(f"  > Parasitic Branch (Rule 2)             : {_s['parasitic_branch']} cases")
    print(f"  > Dual Execution Context (Rule 3)       : {_s['dual_context']} cases")
    print(f"  > DOM Evasion (Rule 4)                  : {_s['evasion_dom']} cases")
    print(f"  > Semantic Cross-Validation (Rule 5)    : {_s['semantic_crossval']} cases")
    print(f"  >   └ Fingerprinting Leak (sub-case)    : {_s['fingerprinting']} cases")
    print(f"  > Camouflaged 3rd-party leak            : {_s['camouflaged_3rd_party']} cases (Core finding!)")
    print("==================================================")
    print(f"📂 Detailed malicious domain blacklist saved as CSV: {CSV_OUTPUT}")