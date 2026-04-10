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
RESULT_DIR        = os.path.expanduser("~/mixed-hermes/pipeline_results")
MIXED_HERMES_ROOT = Path(os.path.expanduser("~/mixed-hermes"))

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
    "login", "signin", "/auth/", "/auth?", "auth.",
    "sso", "oauth", "verify", "returnurl", "logout"
]

# 계열사/자사 CDN 도메인 매핑 (동일 기업이지만 TLD가 다른 도메인)
# is_first_party()에서 이 매핑을 참조하여 1st-party로 판정
AFFILIATED_DOMAINS = {
    "naver.com":     ["pstatic.net", "nstatic.net"],
    "instagram.com": ["facebook.com", "fbcdn.net", "cdninstagram.com"],
    "facebook.com":  ["instagram.com", "fbcdn.net", "cdninstagram.com"],
}

TRACKER_KEYWORDS = [
    # 일반적인 행위 및 로깅 키워드
    "collect", "pixel", "logging", "logger", "/log/", "/log?",
    "beacon", "metric", "analytics", "/ads/", "/ads?", "adserver", "stats",
    "telemetry", "monitor", "insight", "impress", "measure", "report", "trace", "pulse", "record",
    # boundary-aware: 일반 단어와의 충돌 방지
    #   track: soundtrack, backtrack, racetrack 방지
    "tracker", "tracking", "/track/", "/track?", ".track.",
    #   event: preventDefault, eventlistener 방지
    "/event/", "/event?", "event.", "events.",
    #   ping: shopping, mapping, zipping 방지
    "/ping/", "/ping?", "/ping.",
    #   segment: URL path segment 혼동 방지 → Segment.io 플랫폼 특정
    "segment.io", "segment.com", "cdn.segment.",
    # 고도화된 타사 추적자 및 광고 플랫폼 전용 도메인 키워드
    "googletagmanager", "google-analytics", "doubleclick", "criteo", "hotjar", "crazyegg",
    "mixpanel", "appdynamics", "newrelic", "datadog", "facebook"
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
domain_context_map = {}  # domain -> {"AUTONOMOUS": n, "EVENT_DRIVEN": n, "UNKNOWN": n}

# ==========================================
# 🔍 Rule 1: WCC Physical Isolation Detector
# ==========================================
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
# Sink types that are purely for rendering (non-malicious by themselves)
RENDER_SINKS = {"innerHTML", "textContent", "innerText", "outerHTML",
                "insertAdjacentHTML", "value", "document.write"}
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
def detect_dual_context(domain_name, routes, event_driven_count=0):
    """
    Rule 3 (Context Duality — domain-level):
    The domain's script simultaneously contains:
      - EVENT_DRIVEN context: legitimate code triggered by user interaction
      - AUTONOMOUS routes  : tracking code that self-executes silently

    Duality evidence comes from two sources:
      1) Taint routes with trigger_context == EVENT_DRIVEN
      2) Engine metadata: event_driven_functions count (pre-scan of addEventListener/on* bindings)
    When either proves EVENT_DRIVEN presence alongside AUTONOMOUS routes,
    every AUTONOMOUS network/navigation/storage route is flagged.
    """
    trigger_contexts = {r.get("trigger_context", "UNKNOWN") for r in routes}

    has_event_driven = "EVENT_DRIVEN" in trigger_contexts or event_driven_count > 0
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
    "Date", "performance.now", "Math.random",
    # Obfuscated sources (from C++ engine: indirect property / call that couldn't be resolved).
    # Legitimate code has no reason to hide its data origin;
    # when these reach a known tracker endpoint, it is a stronger signal of covert exfiltration.
    "Obfuscated_Property", "Obfuscated_Call", "Dynamic_Source"
}

# Fingerprinting source prefixes: device/browser properties whose network
# transmission constitutes fingerprinting regardless of destination.
# Uses prefix match ("screen.") instead of substring ("screen") to avoid
# false positives like "fullscreen" or "navigator.sendBeacon".
FINGERPRINT_PREFIXES = ("screen.", "navigator.")

def detect_semantic_validation(domain_name, routes, domain_has_tracker=False):
    """
    Rule 5 (Semantic Cross-Validation) — domain-level, two sub-types:

    A) General Semantic:
       destination reputation (tracker keyword) + source sensitivity → confirmed.
       Separates legitimate telemetry from covert surveillance.
       두 가지 증거 경로:
         A-1) Static: route.destination_url 자체에 tracker 키워드 포함
         A-2) Dynamic: destination이 DYNAMIC_URL이지만, 동일 도메인의 network_logs에서
              3rd-party tracker 통신이 실제 관측됨 (Hybrid Cross-Validation)

    B) Fingerprinting (sub-case, mutually exclusive with A per route):
       Source(screen.*/navigator.*) + Sink(Network/Navigation) + Destination(3rd-party).
       Full Data Flow 기반 판정: device 속성이 3rd-party로 전송될 때만 fingerprinting.
       자사 서버 전송(responsive design 등)은 정상 행위이므로 제외.

    Each route is classified as exactly one of {A, B, neither} — never both.
    """
    semantic = []       # General Semantic (A)
    fingerprint = []    # Fingerprinting (B)

    for r in routes:
        dest_url    = r.get("destination_url", "")
        source_name = r.get("source_name", "") or ""
        sink_type   = r.get("sink_type", "")

        # Only check routes that actually exfiltrate data externally
        if sink_type not in {"Network", "Navigation"}:
            continue

        dest_lower = dest_url.lower()

        # (B) Fingerprinting: device-identifying source → 3rd-party tracker (Data Flow 기반)
        is_fingerprint_src = any(source_name.startswith(p) for p in FINGERPRINT_PREFIXES)
        if is_fingerprint_src:
            if not is_first_party(domain_name, dest_url):
                fingerprint.append(r)
            continue  # mutually exclusive — skip general check for this route

        # Whitelist: skip legitimate 1st-party auth/login endpoints (general semantic only)
        if is_first_party(domain_name, dest_url) and any(kw in dest_lower for kw in WHITELIST_KEYWORDS):
            continue

        # (A-1) Static: tracker destination + sensitive source
        is_tracker_dest = any(kw in dest_lower for kw in TRACKER_KEYWORDS)
        is_sensitive_src = any(s in source_name for s in SENSITIVE_SOURCES)

        if is_tracker_dest and is_sensitive_src:
            semantic.append(r)
            continue

        # (A-2) Dynamic (Hybrid): DYNAMIC_URL이지만 domain 단위로 tracker 통신 관측됨
        # 정적 분석이 URL을 복원 못해도, Puppeteer 동적 관측이 tracker 존재를 증명.
        # 민감한 소스 → 네트워크 싱크 + 도메인 내 tracker 관측 = Semantic Cross-Validation 성립.
        if (dest_url == "DYNAMIC_URL" or "{VAR}" in dest_url) and domain_has_tracker and is_sensitive_src:
            r["_semantic_evidence"] = "domain_level"  # 구분 마킹 (Party_Check 라벨용)
            semantic.append(r)

    return semantic, fingerprint


# ==========================================
# 🔍 1st-party(자사) vs 3rd-party(타사) 판별 함수
# ==========================================
def is_first_party(source_domain, dest_url, include_affiliated=True):
    """
    source_domain: 현재 분석 중인 사이트 (예: nexon.com)
    dest_url: 데이터가 날아가는 목적지 URL (예: nxlogin.nexon.com/...)
    include_affiliated: True면 계열사/CDN 도메인도 1st-party로 인정,
                        False면 동일 TLD만 1st-party로 판정 (CNAME 스캔용)
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
        if dest_netloc == base_source or dest_netloc.endswith("." + base_source):
            return True

        # 계열사/자사 CDN 도메인 매핑 확인 (예: pstatic.net → naver.com)
        if include_affiliated:
            for affiliated in AFFILIATED_DOMAINS.get(base_source, []):
                if dest_netloc == affiliated or dest_netloc.endswith("." + affiliated):
                    return True

        return False
    except (ValueError, AttributeError):
        return False

# ==========================================
# 🔍 Party Check 동적 확정 (Unified Rule)
# ==========================================
def determine_unified_party(domain_name, dest_url, sink_type):
    first_party = is_first_party(domain_name, dest_url)
    is_cookie_or_storage = sink_type == "Storage" or any(kw in dest_url for kw in ("path=/", "domain=", "expires="))
    if "CNAME Cloaked" in dest_url:
        return "1st-Party (CNAME Cloaked)"
    elif "Hybrid Reconstructed" in dest_url:
        return "1st-Party (Hybrid)" if first_party else "3rd-Party (Identified)"
    elif is_cookie_or_storage:
        return "Local (Cookie/Storage)"
    elif dest_url == "DYNAMIC_URL" or "{VAR}" in dest_url:
        return "Unknown (Obfuscated)"
    else:
        return "1st-Party" if first_party else "3rd-Party/Unknown"

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
    global stats, malicious_records, domain_context_map

    domain_name = file_path.name.replace("_report.json", "").replace("_log.json", "").replace(".json", "")
    
    # 🌟 [하이브리드 교차검증] 크롤러가 수집해 둔 실제 네트워크 로그 불러오기
    network_log_file = MIXED_HERMES_ROOT / "crawler" / "collected_scripts" / domain_name / "network_logs.json"

    network_url_list = []
    if network_log_file.exists():
        try:
            with open(network_log_file, 'r', encoding='utf-8') as nlf:
                network_url_list = json.load(nlf)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"  [⚠️  Warning] network_logs parse failed for {domain_name}: {e}")
    else:
        print(f"  [⚠️  Warning] network_logs.json not found for {domain_name}: {network_log_file}")

    # Domain-level tracker 관측 여부 (Rule 5 A-2 Hybrid Evidence용)
    # network_logs에 3rd-party tracker URL이 하나라도 있으면 True
    domain_has_tracker = any(
        not is_first_party(domain_name, url) and
        any(kw in url.lower() for kw in TRACKER_KEYWORDS)
        for url in network_url_list
    )

    # 도메인에서 실제 관측된 3rd-party tracker 목록 (Observed_Trackers 컬럼용)
    observed_tracker_domains = sorted(set(
        urlparse(url).netloc
        for url in network_url_list
        if not is_first_party(domain_name, url)
        and any(kw in url.lower() for kw in TRACKER_KEYWORDS)
        and url.startswith("http")
    ))
    observed_trackers_str = " | ".join(observed_tracker_domains) if observed_tracker_domains else ""

    
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return

    is_malicious = False
    domain_threats = []

    routes = data.get("s2s_routes", [])

    # 도메인별 실행 컨텍스트 분포 수집 (Rule 3 혼합 증거용)
    ctx_counts = {"AUTONOMOUS": 0, "EVENT_DRIVEN": 0, "UNKNOWN": 0}
    for r in routes:
        ctx = r.get("trigger_context", "UNKNOWN")
        ctx_counts[ctx] = ctx_counts.get(ctx, 0) + 1
    ctx_counts["event_driven_functions"] = data.get("event_driven_functions", 0)
    domain_context_map[domain_name] = ctx_counts

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
        # Sink-type-aware URL resolution: Source → Sink → Destination 전체 Data Flow 기반
        predicted_url = None
        is_hybrid_eligible = ("{VAR}" in dest_url)

        # Phase 0: Cookie/Storage 패턴 감지
        # destination_url이 URL이 아닌 cookie 문자열인 경우를 식별.
        # 예: "{VAR}=; path=/; domain=nexon.com; expires={VAR};"
        is_cookie_pattern = any(kw in dest_url for kw in ("path=/", "domain=", "expires="))

        # Phase 1: Hybrid Reconstruction (조각 맞추기)
        # {VAR} 패턴이 포함된 부분 URL을 network_logs의 실제 URL과 매칭해 복원.
        # cookie 문자열(path=/, domain= 등)은 URL이 아니므로 건너뜀.
        # 복원 실패 or 순수 DYNAMIC_URL → 그대로 DYNAMIC_URL 유지 (보수적 표기)
        if is_hybrid_eligible and not is_cookie_pattern:
            static_fragments = [frag for frag in dest_url.split("{VAR}") if len(frag.strip()) >= 2]
            if static_fragments:
                for real_url in network_url_list:
                    if all(frag in real_url for frag in static_fragments):
                        predicted_url = real_url + " (🌟 Hybrid Reconstructed)"
                        break
                            
        # Phase 2: CNAME Cloaking 스캔 — netloc에만 tracker 키워드 체크
        # CNAME Cloaking은 동일 TLD 서브도메인만 해당 (계열사 도메인 제외)
        if not predicted_url and (dest_url == "DYNAMIC_URL" or is_hybrid_eligible) and not is_cookie_pattern:
            for real_url in network_url_list:
                if is_first_party(domain_name, real_url, include_affiliated=False) and real_url.startswith("http"):
                    netloc_only = urlparse(real_url).netloc.lower()
                    if any(t_key in netloc_only for t_key in TRACKER_KEYWORDS):
                        predicted_url = real_url + " (🌟 Predicted 1st-Party Target / CNAME Cloaked)"
                        break

        if predicted_url:
            dest_url = predicted_url
            route["destination_url"] = dest_url

        # 🌟 1st-party 여부와 화이트리스트 키워드 포함 여부를 동시에 검사
        first_party = is_first_party(domain_name, dest_url)
        dest_url_lower = dest_url.lower()
        has_whitelist_keyword = any(keyword in dest_url_lower for keyword in WHITELIST_KEYWORDS)

        # 🌟 Party Check 동적 확정 로직 (논문용 세밀화)
        party_check = determine_unified_party(domain_name, dest_url, sink_type)

        # ── Collect all independent rule matches for this route ──
        active_rules = []  # list of (threat_type, party_check) tuples

        # [Rule 4] DOM Evasion — img.src / frame.href bypass (exfiltration only)
        if "(Evasion Suspected)" in sink_name and sink_type in {"Network", "Navigation"}:
            if has_whitelist_keyword and first_party:
                pass  # 🟢 Whitelist: legitimate 1st-party login — skip entirely
            elif has_whitelist_keyword and not first_party:
                # {VAR} 포함 URL은 도메인 자체가 불명 → Camouflage 확정 불가, Dynamic Obfuscated로 처리
                if "{VAR}" in dest_url or dest_url == "DYNAMIC_URL":
                    active_rules.append(("DOM_Evasion (Dynamic Obfuscated)", party_check))
                    stats["evasion_dynamic"] += 1
                else:
                    active_rules.append(("Evasion_with_Camouflage (Disguised Tracker)", party_check))
                    stats["camouflaged_3rd_party"] += 1
            else:
                # {VAR} 포함 URL도 목적지 미확정 → Dynamic Obfuscated
                is_dest_unresolved = (dest_url == "DYNAMIC_URL" or "{VAR}" in dest_url)
                label = "DOM_Evasion (Dynamic Obfuscated)" if is_dest_unresolved else "DOM_Evasion (Rule 4)"
                active_rules.append((label, party_check))
                if is_dest_unresolved:
                    stats["evasion_dynamic"] += 1
                else:
                    stats["evasion_dom"] += 1

        # NOTE: Fingerprinting is now handled inside detect_semantic_validation()
        #       at domain level (mutually exclusive with general Rule 5).

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
                "Observed_Trackers": observed_trackers_str,
                "Party_Check": p_check
            })

    # ── Rule 1, 2, 3, 5: 항상 독립적으로 실행 (Rule 4 결과와 무관) ──
    event_driven_count = data.get("event_driven_functions", 0)
    isolated = detect_isolated_exfil(domain_name, routes)
    parasitic = detect_parasitic_branch(domain_name, routes)
    dual      = detect_dual_context(domain_name, routes, event_driven_count)
    semantic, fingerprint = detect_semantic_validation(domain_name, routes, domain_has_tracker)

    if domain_threats or isolated or parasitic or dual or semantic or fingerprint:
        is_malicious = True
        stats["total_malicious"] += 1
        malicious_records.extend(domain_threats)

        # ── Rule 1: WCC isolation check ──
        for r in isolated:
            src       = r.get("source_name", "") or "Unknown"
            sink_name = r.get("sink_name", "")
            dest_url  = r.get("destination_url", "DYNAMIC_URL")
            tctx      = r.get("trigger_context", "UNKNOWN")
            already_flagged = any(
                rec["Leaked_Data (Source)"] == src and rec["Leak_Method (Sink)"] == sink_name
                and rec["Destination"] == dest_url
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
                    "Observed_Trackers": observed_trackers_str,
                    "Party_Check": "Unknown (WCC Isolated)"
                })

        # ── Rule 2: Parasitic branch check ──
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
                "Observed_Trackers": observed_trackers_str,
                "Party_Check": "3rd-Party (Parasitic)"
            })

        # ── Rule 3: Domain-level dual execution context ──
        for r in dual:
            src       = r.get("source_name", "") or "Unknown"
            sink_name = r.get("sink_name", "")
            dest_url  = r.get("destination_url", "DYNAMIC_URL")
            # Rule 3 is a domain-level structural property:
            # record every AUTONOMOUS route as evidence of duality,
            # even if also captured by Rule 4 (they are different threat dimensions)
            stats["dual_context"] += 1
            # Party_Check: 실제 destination 기반 판정 (하드코딩 제거)
            r3_party = determine_unified_party(domain_name, dest_url, r.get("sink_type", ""))
            malicious_records.append({
                "Domain": domain_name,
                "Threat_Type": "Dual_Execution_Context (Rule 3)",
                "Trigger_Context": "AUTONOMOUS",
                "Leaked_Data (Source)": src,
                "Leak_Method (Sink)": sink_name,
                "Destination": dest_url,
                "Observed_Trackers": observed_trackers_str,
                "Party_Check": r3_party
            })

        # ── Rule 5a: Semantic Cross-Validation (general) ──
        for r in semantic:
            src       = r.get("source_name", "") or "Unknown"
            sink_name = r.get("sink_name", "")
            dest_url  = r.get("destination_url", "DYNAMIC_URL")
            tctx      = r.get("trigger_context", "UNKNOWN")
            is_domain_level = r.pop("_semantic_evidence", None) == "domain_level"
            # 증거 강도에 따라 Threat_Type 분기
            if is_domain_level:
                threat_label = "Semantic_CrossValidation (Rule 5) [Probabilistic]"
                party = "3rd-Party (Domain-level Evidence)"
            else:
                threat_label = "Semantic_CrossValidation (Rule 5) [Deterministic]"
                party = "Confirmed 3rd-Party Tracker (Semantic)"
            stats["semantic_crossval"] += 1
            malicious_records.append({
                "Domain": domain_name,
                "Threat_Type": threat_label,
                "Trigger_Context": tctx,
                "Leaked_Data (Source)": src,
                "Leak_Method (Sink)": sink_name,
                "Destination": dest_url,
                "Observed_Trackers": observed_trackers_str,
                "Party_Check": party
            })

        # ── Rule 5b: Fingerprinting Leak (mutually exclusive with 5a) ──
        for r in fingerprint:
            src       = r.get("source_name", "") or "Unknown"
            sink_name = r.get("sink_name", "")
            dest_url  = r.get("destination_url", "DYNAMIC_URL")
            tctx      = r.get("trigger_context", "UNKNOWN")
            fp_party  = "1st-Party" if is_first_party(domain_name, dest_url) else "3rd-Party/Unknown"
            stats["fingerprinting"] += 1
            malicious_records.append({
                "Domain": domain_name,
                "Threat_Type": "Fingerprinting_Leak (Rule 5)",
                "Trigger_Context": tctx,
                "Leaked_Data (Source)": src,
                "Leak_Method (Sink)": sink_name,
                "Destination": dest_url,
                "Observed_Trackers": observed_trackers_str,
                "Party_Check": fp_party
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
    parser.add_argument("--summary", action="store_true", help="Generate a per-domain summary table CSV for paper use")
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
            "Isolated_Exfiltration (Rule 1)":                         1,
            "Parasitic_Branch (Rule 2)":                               2,
            "Dual_Execution_Context (Rule 3)":                         3,
            "DOM_Evasion (Rule 4)":                                    4,
            "DOM_Evasion (Dynamic Obfuscated)":                        4,
            "Evasion_with_Camouflage (Disguised Tracker)":             4,
            "Semantic_CrossValidation (Rule 5) [Deterministic]":       5,
            "Semantic_CrossValidation (Rule 5) [Probabilistic]":       5,
            "Fingerprinting_Leak (Rule 5)":                            5,
        }

        # ── Deduplication ──────────────────────────────────────────────────
        # Group records by (Domain, Source, Sink, Destination).
        # When multiple rules fire on the same taint route, merge them into
        # one row with combined Threat_Type labels instead of separate rows.
        def _normalize_dest(dest: str) -> str:
            if not dest or dest == "DYNAMIC_URL": return "DYNAMIC_URL"
            if "{VAR}" in dest: return "DYNAMIC_URL"
            if "Predicted" in dest or "Hybrid Reconstructed" in dest or "CNAME Cloaked" in dest:
                return "DYNAMIC_URL"
            return dest

        dedup: dict = {}  # key -> merged record
        for rec in malicious_records:
            dest_norm = _normalize_dest(rec.get("Destination", ""))
            key = (
                rec.get("Domain", ""),
                rec.get("Leaked_Data (Source)", ""),
                rec.get("Leak_Method (Sink)", ""),
                dest_norm,
            )
            threat = rec.get("Threat_Type", "")
            if key not in dedup:
                dedup[key] = dict(rec)
            else:
                existing = dedup[key]["Threat_Type"]
                if threat not in existing:
                    dedup[key]["Threat_Type"] = existing + " | " + threat
                
                # 중첩 Threat_Type 정리 (Rule 4가 있으면 Obfuscated 제거)
                if "DOM_Evasion (Rule 4)" in dedup[key]["Threat_Type"] and "DOM_Evasion (Dynamic Obfuscated)" in dedup[key]["Threat_Type"]:
                    labels = dedup[key]["Threat_Type"].split(" | ")
                    labels = sorted(set(l for l in labels if l != "DOM_Evasion (Dynamic Obfuscated)"))
                    dedup[key]["Threat_Type"] = " | ".join(labels)

                # 더 구체적인 Destination으로 업그레이드 및 Party_Check 갱신
                if dedup[key]["Destination"] == "DYNAMIC_URL" and rec.get("Destination", "") != "DYNAMIC_URL":
                    dedup[key]["Destination"] = rec.get("Destination", "DYNAMIC_URL")
                    # Destination이 구체화되었으므로 Party_Check 재산정 (단, Rule 5 Deterministic 등 확정 레이블 보존)
                    new_party = determine_unified_party(dedup[key]["Domain"], dedup[key]["Destination"], dedup[key]["Leak_Method (Sink)"])
                    if "WCC Isolated" not in dedup[key]["Party_Check"] and "Confirmed 3rd-Party" not in dedup[key]["Party_Check"]:
                        dedup[key]["Party_Check"] = new_party

        deduped = list(dedup.values())

        # Sort deduplicated rows by lowest rule number present, then domain
        def sort_key(rec):
            labels = rec.get("Threat_Type", "").split(" | ")
            min_rule = min(RULE_ORDER.get(lbl, 99) for lbl in labels)
            return (min_rule, rec.get("Domain", ""))

        deduped.sort(key=sort_key)

        # ── Confidence Score 계산 ──────────────────────────────────────────
        # 각 deduped 행에 Confidence_Score (1~5) 부여:
        #   +1 per unique Rule fired (up to 3)
        #   +1 if AUTONOMOUS context
        #   +1 if Hybrid/Predicted 3rd-Party destination (dynamic confirmation)
        def compute_confidence(rec: dict) -> int:
            score = 0
            labels = [l.strip() for l in rec.get("Threat_Type", "").split(" | ")]
            rule_nums = {RULE_ORDER.get(l, 99) for l in labels if RULE_ORDER.get(l, 99) != 99}
            score += min(len(rule_nums), 3)          # 최대 +3 (Rule 수)
            if rec.get("Trigger_Context") == "AUTONOMOUS":
                score += 1                           # +1 자율실행
            dest = rec.get("Destination", "")
            if "Predicted 3rd-Party" in dest or "Hybrid Reconstructed" in dest or "CNAME Cloaked" in dest:
                score += 1                           # +1 동적 확인
            return max(1, min(score, 5))             # 1~5 범위 클램프

        for rec in deduped:
            rec["Confidence_Score"] = compute_confidence(rec)

        # ── Post-dedup Party_Check refinement ──────────────────────────────
        # Rule 1 hardcodes Party_Check as "Unknown (WCC Isolated)" at append time.
        # After merging, if the same row also carries Rule 5 (semantic confirmation)
        # or a Predicted/Hybrid 3rd-party destination, the party is no longer unknown.
        for rec in deduped:
            threat = rec.get("Threat_Type", "")
            dest   = rec.get("Destination", "")
            if "Isolated_Exfiltration (Rule 1)" in threat and "WCC Isolated" in rec.get("Party_Check", ""):
                # Rule 5가 추가로 존재하거나, 동적 분석을 통해 타겟지가 파악되었을 때 Party_Check를 구체화
                if "CNAME Cloaked" in dest:
                    rec["Party_Check"] = "1st-Party (CNAME Cloaked)"
                elif "Hybrid Reconstructed" in dest and "1st-Party" in determine_unified_party(rec["Domain"], dest, rec["Leak_Method (Sink)"]):
                    rec["Party_Check"] = "1st-Party (Hybrid)"
                elif ("Semantic_CrossValidation (Rule 5)" in threat or
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
            "evasion_dynamic":     0,
            "fingerprinting":      0,
            "semantic_crossval":   0,
            "camouflaged_3rd_party": 0,
        }
        LABEL_TO_STAT = {
            "Isolated_Exfiltration (Rule 1)":                         "isolated_exfil",
            "Parasitic_Branch (Rule 2)":                               "parasitic_branch",
            "Dual_Execution_Context (Rule 3)":                         "dual_context",
            "DOM_Evasion (Rule 4)":                                    "evasion_dom",
            "DOM_Evasion (Dynamic Obfuscated)":                        "evasion_dynamic",
            "Evasion_with_Camouflage (Disguised Tracker)":             "camouflaged_3rd_party",
            "Semantic_CrossValidation (Rule 5) [Deterministic]":       "semantic_crossval",
            "Semantic_CrossValidation (Rule 5) [Probabilistic]":       "semantic_crossval",
            "Fingerprinting_Leak (Rule 5)":                            "fingerprinting",
        }
        for rec in deduped:
            seen_stats = set()
            for label in rec.get("Threat_Type", "").split(" | "):
                label = label.strip()
                stat_key = LABEL_TO_STAT.get(label)
                if stat_key and stat_key not in seen_stats:
                    final_stats[stat_key] += 1
                    seen_stats.add(stat_key)

        FIELDNAMES = [
            "Domain", "Threat_Type", "Trigger_Context",
            "Leaked_Data (Source)", "Leak_Method (Sink)",
            "Destination", "Observed_Trackers", "Party_Check", "Confidence_Score"
        ]
        with open(CSV_OUTPUT, 'w', newline='', encoding='utf-8-sig') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=FIELDNAMES)
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
            writer.writerow(["DOM Evasion (Rule 4)",                     f"{final_stats['evasion_dom'] + final_stats['evasion_dynamic']} cases"])
            writer.writerow(["  └ Destination Identified",                 f"{final_stats['evasion_dom']} cases"])
            writer.writerow(["  └ Destination Hidden (Dynamic Obfuscated)", f"{final_stats['evasion_dynamic']} cases"])
            writer.writerow(["Semantic Cross-Validation (Rule 5)",       f"{final_stats['semantic_crossval']} cases"])
            writer.writerow(["  └ [Deterministic] URL confirmed tracker",    f"{sum(1 for r in deduped if 'Deterministic' in r.get('Threat_Type',''))} cases"])
            writer.writerow(["  └ [Probabilistic] Domain-inferred tracker",  f"{sum(1 for r in deduped if 'Probabilistic' in r.get('Threat_Type',''))} cases"])
            writer.writerow(["  └ Fingerprinting Leak (Rule 5 sub-case)",     f"{final_stats['fingerprinting']} cases"])
            writer.writerow(["Camouflaged 3rd-party leak",                f"{final_stats['camouflaged_3rd_party']} cases (Core finding!)"])

            # 도메인별 혼합추적자 증거 요약
            writer.writerow([])
            writer.writerow(["[Per-Domain Mixed Tracker Evidence]"])
            # 도메인별 Rule 히트 집계
            domain_rules: dict = {}
            for rec in deduped:
                dom = rec["Domain"]
                if dom not in domain_rules:
                    domain_rules[dom] = set()
                for label in rec.get("Threat_Type", "").split(" | "):
                    rnum = RULE_ORDER.get(label.strip())
                    if rnum:
                        domain_rules[dom].add(rnum)
            for dom in sorted(domain_context_map.keys()):
                ctx = domain_context_map[dom]
                auto = ctx.get("AUTONOMOUS", 0)
                event = ctx.get("EVENT_DRIVEN", 0)
                ed_funcs = ctx.get("event_driven_functions", 0)
                rules_hit = sorted(domain_rules.get(dom, set()))
                rules_str = ",".join(f"R{r}" for r in rules_hit) if rules_hit else "None"
                is_dual = (auto > 0) and (event > 0 or ed_funcs > 0)
                ctx_label = "Mixed (Dual Context)" if is_dual else "Single Context"
                writer.writerow([f"  {dom}", f"Routes: AUTONOMOUS={auto} EVENT_DRIVEN={event} | Handlers={ed_funcs} ({ctx_label})", f"Rules: {rules_str}"])

        # ── --summary: 도메인별 요약 테이블 ────────────────────────────────
        if args.summary:
            summary_path = CSV_OUTPUT.replace(".csv", "_summary.csv")
            domain_summary: dict = {}
            for rec in deduped:
                dom = rec["Domain"]
                if dom not in domain_summary:
                    domain_summary[dom] = {
                        "Domain": dom,
                        "Rule_1": 0, "Rule_2": 0, "Rule_3": 0,
                        "Rule_4": 0, "Rule_5": 0,
                        "Total_Routes": 0,
                        "Max_Confidence": 0,
                        "3rd_Party_Confirmed": 0,
                    }
                entry = domain_summary[dom]
                entry["Total_Routes"] += 1
                entry["Max_Confidence"] = max(entry["Max_Confidence"], rec.get("Confidence_Score", 1))
                if "3rd-Party" in rec.get("Party_Check", ""):
                    entry["3rd_Party_Confirmed"] += 1
                for label in rec.get("Threat_Type", "").split(" | "):
                    rnum = RULE_ORDER.get(label.strip(), 0)
                    if 1 <= rnum <= 5:
                        entry[f"Rule_{rnum}"] += 1

            summary_rows = sorted(domain_summary.values(), key=lambda r: -r["Total_Routes"])
            with open(summary_path, 'w', newline='', encoding='utf-8-sig') as sf:
                sw = csv.DictWriter(sf, fieldnames=["Domain","Rule_1","Rule_2","Rule_3","Rule_4","Rule_5","Total_Routes","Max_Confidence","3rd_Party_Confirmed"])
                sw.writeheader()
                sw.writerows(summary_rows)
            print(f"📋 Per-domain summary saved: {summary_path}")


    # final_stats is available only if malicious_records existed; fall back to raw stats otherwise
    _s = final_stats if malicious_records else stats
    print("✅ Analysis Complete! [Final Statistical Report]")
    print(f"- Total domains scanned : {_s['total_scanned']}")
    print(f"- 🚨 Malicious tracker infected domains : {_s['total_malicious']}\n")
    print("[Detailed Evasion Technique Statistics]")
    print(f"  > Isolated Exfiltration (Rule 1)        : {_s['isolated_exfil']} cases")
    print(f"  > Parasitic Branch (Rule 2)             : {_s['parasitic_branch']} cases")
    print(f"  > Dual Execution Context (Rule 3)       : {_s['dual_context']} cases")
    print(f"  > DOM Evasion (Rule 4)                  : {_s['evasion_dom'] + _s['evasion_dynamic']} cases")
    print(f"  >   └ Destination Identified             : {_s['evasion_dom']} cases")
    print(f"  >   └ Destination Hidden (Dyn. Obfusc.) : {_s['evasion_dynamic']} cases")
    print(f"  > Semantic Cross-Validation (Rule 5)    : {_s['semantic_crossval']} cases")
    print(f"  >   └ Fingerprinting Leak (sub-case)    : {_s['fingerprinting']} cases")
    print(f"  > Camouflaged 3rd-party leak            : {_s['camouflaged_3rd_party']} cases (Core finding!)")
    print("==================================================")
    print(f"📂 Detailed malicious domain blacklist saved as CSV: {CSV_OUTPUT}")