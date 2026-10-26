import os
import json
import csv
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

                                            
            
                                            
RESULT_DIR        = os.path.expanduser("~/mixed-hermes/pipeline_results")
MIXED_HERMES_ROOT = Path(os.path.expanduser("~/mixed-hermes"))

def _resolve_csv_path():
    """Generate a non-colliding timestamped CSV filename inside reports/."""
    base_dir = os.path.expanduser("~/mixed-hermes/csv_reports")
    os.makedirs(base_dir, exist_ok=True)                              
    date_str = datetime.now().strftime("%Y%m%d")
    base_name = f"malicious_domains_{date_str}"
    candidate = os.path.join(base_dir, f"{base_name}.csv")
    counter = 2
    while os.path.exists(candidate):
        candidate = os.path.join(base_dir, f"{base_name}_{counter}.csv")
        counter += 1
    return candidate

CSV_OUTPUT = _resolve_csv_path()
DOMAIN_FINDINGS_CSV = CSV_OUTPUT.replace("malicious_domains_", "domain_findings_")
DOMAIN_FINDINGS_JSON = DOMAIN_FINDINGS_CSV.replace(".csv", ".json")

                                            
                                          
                                            
WHITELIST_KEYWORDS = [
    "login", "signin", "/auth/", "/auth?", "auth.",
    "sso", "oauth", "verify", "returnurl", "logout"
]

                                                                              
                                                             
AFFILIATED_DOMAINS = {
    "naver.com":     ["pstatic.net", "nstatic.net"],
    "instagram.com": ["facebook.com", "fbcdn.net", "cdninstagram.com"],
    "facebook.com":  ["instagram.com", "fbcdn.net", "cdninstagram.com"],
}

TRACKER_KEYWORDS = [
                                           
    "collect", "pixel", "logging", "logger", "/log/", "/log?",
    "beacon", "metric", "analytics", "/ads/", "/ads?", "adserver", "stats",
    "telemetry", "monitor", "insight", "impress", "measure", "report", "trace", "pulse", "record",
                                                                    
                                                     
    "tracker", "tracking", "/track/", "/track?", ".track.",
                                                  
    "/event/", "/event?", "event.", "events.",
                                              
    "/ping/", "/ping?", "/ping.",
                                                                              
    "segment.io", "segment.com", "cdn.segment.",
                                                                   
    "googletagmanager", "google-analytics", "doubleclick", "criteo", "hotjar", "crazyegg",
    "mixpanel", "appdynamics", "newrelic", "datadog", "facebook"
]

                                            
                     
                                            
stats = {
    "total_scanned": 0,
    "total_malicious": 0,
    "evasion_dom": 0,
    "evasion_dynamic": 0,
    "fingerprinting": 0,
    "camouflaged_3rd_party": 0,
    "dual_context": 0,                                                         
    "isolated_exfil": 0,                                                    
    "parasitic_branch": 0,                                                          
    "semantic_crossval": 0                                                         
}

malicious_records = []
domain_context_map = {}                                                                

                                            
                                           
                                            
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
                                                                   
    UI_INDICATOR_NODES = {"StoreFrameInst", "PhiInst", "LoadFrameInst"}

    isolated_routes = []
    for r in routes:
        path_nodes = r.get("path_nodes", [])
        sink_type  = r.get("sink_type", "")

                                                                  
        if sink_type not in {"Network", "Navigation"}:
            continue

                                                                              
        has_ui_node = any(node in UI_INDICATOR_NODES for node in path_nodes)
        if not has_ui_node and path_nodes:                          
            isolated_routes.append(r)

    return isolated_routes


                                            
                                     
                                            
                                                                        
RENDER_SINKS = {"innerHTML", "textContent", "innerText", "outerHTML",
                "insertAdjacentHTML", "value", "document.write"}
def detect_parasitic_branch(domain_name, routes):
    """
    Rule 2 (Parasitic Branch):
    Same Source feeds BOTH a rendering sink (normal UI) AND a
    Network/Navigation sink (exfiltration) at the same time.
    This is the classic 'parasite' pattern — piggybacks on legitimate data flow.
    """
                            
    source_groups = {}
    for r in routes:
        src = r.get("source_name", "") or "[Dynamic_Source]"
        source_groups.setdefault(src, []).append(r)

    parasitic = []
    for src, src_routes in source_groups.items():
        sink_types  = {r.get("sink_type", "") for r in src_routes}
        sink_names  = [r.get("sink_name", "") for r in src_routes]

                                                                  
        has_render_sink = any(
            any(rs in sn for rs in RENDER_SINKS) for sn in sink_names
        ) or "Render" in sink_types
        has_net_sink = sink_types & {"Network", "Navigation"}

        if has_render_sink and has_net_sink:
                                                                          
            for r in src_routes:
                if r.get("sink_type", "") in {"Network", "Navigation"}:
                    parasitic.append(r)
    return parasitic

                                            
                                                          
                                            
def detect_dual_context(domain_name, routes):
    """
    Evaluate Rule 3 as a domain-level structural property.

    A domain satisfies R3 only when its actual taint routes contain both an
    AUTONOMOUS route and an EVENT_DRIVEN route.  The engine's
    event_driven_functions count is diagnostic metadata and is deliberately
    not accepted as a substitute for an EVENT_DRIVEN taint route.

    The returned route lists are evidence for the domain-level finding; R3
    does not independently assert that each evidence route is malicious.
    """
    eligible_routes = [
        r for r in routes
        if r.get("route_id") is not None
        and bool(r.get("path_nodes"))
        and r.get("trigger_context") in {"AUTONOMOUS", "EVENT_DRIVEN"}
    ]
    autonomous_routes = [
        r for r in eligible_routes if r.get("trigger_context") == "AUTONOMOUS"
    ]
    event_driven_routes = [
        r for r in eligible_routes if r.get("trigger_context") == "EVENT_DRIVEN"
    ]
    unknown_context_routes = [
        r for r in routes
        if r.get("route_id") is not None
        and bool(r.get("path_nodes"))
        and r.get("trigger_context", "UNKNOWN") not in {"AUTONOMOUS", "EVENT_DRIVEN"}
    ]
    ineligible_routes = [
        r for r in routes
        if r not in eligible_routes and r not in unknown_context_routes
    ]
    is_dual_context = bool(autonomous_routes and event_driven_routes)

    return {
        "domain_name": domain_name,
        "is_dual_context": is_dual_context,
        "autonomous_routes": autonomous_routes,
        "event_driven_routes": event_driven_routes,
        "unknown_context_routes": unknown_context_routes,
        "ineligible_routes": ineligible_routes,
    }


                                            
                                                             
                                            
                                                  
SENSITIVE_SOURCES = {
    "location.href", "location.hostname", "location.origin", "location.pathname",
    "document.URL", "document.cookie",
    "screen.width", "screen.height", "screen.colorDepth",
    "navigator.userAgent", "navigator.language", "navigator.platform",
                                             
    "Date", "performance.now", "Math.random",
                                                                                               
                                                            
                                                                                                
    "Obfuscated_Property", "Obfuscated_Call", "Dynamic_Source"
}

                                                                         
                                                                    
                                                                        
                                                              
FINGERPRINT_PREFIXES = ("screen.", "navigator.")

def detect_semantic_validation(domain_name, routes, domain_has_tracker=False):
    """
    Rule 5 (Semantic Cross-Validation) — domain-level, two sub-types:

    A) General Semantic:
       destination reputation (tracker keyword) + source sensitivity → confirmed.
       Separates legitimate telemetry from covert surveillance.
       Two evidence paths:
         A-1) Static: route.destination_url itself contains a tracker keyword.
         A-2) Dynamic: destination is DYNAMIC_URL, but the domain's network_logs
              show actual third-party tracker traffic (Hybrid Cross-Validation).

    B) Fingerprinting (sub-case, mutually exclusive with A per route):
       Source(screen.*/navigator.*) + Sink(Network/Navigation) + Destination(3rd-party).
       Full data-flow based: only flag fingerprinting when device attributes are
       sent to a third party. First-party transmissions (e.g., responsive design)
       are normal behavior and excluded.

    Each route is classified as exactly one of {A, B, neither} — never both.
    """
    semantic = []                             
    fingerprint = []                        

    for r in routes:
        dest_url    = r.get("destination_url", "")
        source_name = r.get("source_name", "") or ""
        sink_type   = r.get("sink_type", "")

                                                                    
        if sink_type not in {"Network", "Navigation"}:
            continue

        dest_lower = dest_url.lower()

                                                                                             
        is_fingerprint_src = any(source_name.startswith(p) for p in FINGERPRINT_PREFIXES)
        if is_fingerprint_src:
            if not is_first_party(domain_name, dest_url):
                fingerprint.append(r)
            continue                                                          

                                                                                           
        if is_first_party(domain_name, dest_url) and any(kw in dest_lower for kw in WHITELIST_KEYWORDS):
            continue

                                                              
        is_tracker_dest = any(kw in dest_lower for kw in TRACKER_KEYWORDS)
        is_sensitive_src = any(s in source_name for s in SENSITIVE_SOURCES)

        if is_tracker_dest and is_sensitive_src:
            semantic.append(r)
            continue

                                                                                                          
                                                                                       
                                                                                       
                                                                  
        if (dest_url == "DYNAMIC_URL" or "{VAR}" in dest_url) and domain_has_tracker and is_sensitive_src:
            r["_semantic_evidence"] = "domain_level"                                         
            semantic.append(r)

    return semantic, fingerprint


                                            
                                  
                                            
def is_first_party(source_domain, dest_url, include_affiliated=True):
    """
    source_domain: the site under analysis (e.g., nexon.com).
    dest_url: the destination URL the data is sent to (e.g., nxlogin.nexon.com/...).
    include_affiliated: if True, treat affiliate/CDN domains as first-party as well;
                        if False, only the same TLD is first-party (used for CNAME scans).
    """
    if dest_url == "DYNAMIC_URL" or not dest_url.startswith("http"):
        return False                                                                                       

    try:
                                                                                        
        parsed_uri = urlparse(dest_url)
        dest_netloc = parsed_uri.netloc.lower()

                                                      
        base_source = source_domain.replace("www.", "").lower()

                                                                                  
        if dest_netloc == base_source or dest_netloc.endswith("." + base_source):
            return True

                                                                          
        if include_affiliated:
            for affiliated in AFFILIATED_DOMAINS.get(base_source, []):
                if dest_netloc == affiliated or dest_netloc.endswith("." + affiliated):
                    return True

        return False
    except (ValueError, AttributeError):
        return False

                                            
                            
                                            
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

                                            
                                         
                                            
def infer_unknown_source(route: dict) -> str:
    """
    Heuristically infer a source label from sink/path info when source_name is empty.

    Why this is needed: the Hephaistos C++ engine cannot trace the original
    source through very short indirect property chains such as a 2-hop
    LoadPropertyInst → StorePropertyInst (e.g. obj.prop → frame.href directly).

    Rules:
      1. LoadFrameInst sink → indirect frame-property read (DOM Indirect Read)
      2. createElement sink → property of a dynamically created element (Dynamic Element)
      3. window.open / location.href + 2-hop → minimal-chain indirect navigation
      4. document.cookie / sessionStorage sink → session/cookie write of unknown origin
      5. otherwise → Generic Indirect Property
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

                                            
                   
                                            
def analyze_json(file_path, draw_graphs=False):
    global stats, malicious_records, domain_context_map

    domain_name = file_path.name.replace("_report.json", "").replace("_log.json", "").replace(".json", "")
    domain_name = domain_name.strip().lower().rstrip(".")

                                                                                    
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

                                                                                 
                                                                           
    domain_has_tracker = any(
        not is_first_party(domain_name, url) and
        any(kw in url.lower() for kw in TRACKER_KEYWORDS)
        for url in network_url_list
    )

                                                                                                     
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

                                                                           
    ctx_counts = {"AUTONOMOUS": 0, "EVENT_DRIVEN": 0, "UNKNOWN": 0}
    for r in routes:
        ctx = r.get("trigger_context", "UNKNOWN")
        ctx_counts[ctx] = ctx_counts.get(ctx, 0) + 1
    context_bases = {
        r.get("trigger_context_basis", "LEGACY_UNSPECIFIED") for r in routes
    }
    if not context_bases:
        ctx_counts["r3_context_basis"] = "NO_ROUTES"
    elif context_bases == {"SINK_EXECUTION_CHAIN"}:
        ctx_counts["r3_context_basis"] = "SINK_EXECUTION_CHAIN"
    elif len(context_bases) == 1:
        ctx_counts["r3_context_basis"] = next(iter(context_bases))
    else:
        ctx_counts["r3_context_basis"] = "MIXED_OR_PARTIAL"
    ctx_counts["event_driven_functions"] = data.get("event_driven_functions", 0)
    domain_context_map[domain_name] = ctx_counts

    for route in routes:
        sink_name = route.get("sink_name", "")
        sink_type = route.get("sink_type", "")
        source_name = route.get("source_name", "") or ""
        dest_url = route.get("destination_url", "")

                                                                                            
        if not source_name.strip():
            source_name = infer_unknown_source(route)
            route["source_name"] = source_name                                                   

        threat_type = None
        trigger_context = route.get("trigger_context", "UNKNOWN")

                                 
                                                                                                 
        predicted_url = None
        is_hybrid_eligible = ("{VAR}" in dest_url)

                                                  
                                                                       
                                                                     
        is_cookie_pattern = any(kw in dest_url for kw in ("path=/", "domain=", "expires="))

                                                             
                                                                                                  
                                                                              
                                                                                                
        if is_hybrid_eligible and not is_cookie_pattern:
            static_fragments = [frag for frag in dest_url.split("{VAR}") if len(frag.strip()) >= 2]
            if static_fragments:
                for real_url in network_url_list:
                    if all(frag in real_url for frag in static_fragments):
                        predicted_url = real_url + " (🌟 Hybrid Reconstructed)"
                        break

                                                                                        
                                                                                          
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

                                                                              
        first_party = is_first_party(domain_name, dest_url)
        dest_url_lower = dest_url.lower()
        has_whitelist_keyword = any(keyword in dest_url_lower for keyword in WHITELIST_KEYWORDS)

                                                               
        party_check = determine_unified_party(domain_name, dest_url, sink_type)

                                                                   
        active_rules = []                                             

                                                                                
        if "(Evasion Suspected)" in sink_name and sink_type in {"Network", "Navigation"}:
            if has_whitelist_keyword and first_party:
                pass                                                            
            elif has_whitelist_keyword and not first_party:
                                                                                                                        
                if "{VAR}" in dest_url or dest_url == "DYNAMIC_URL":
                    active_rules.append(("DOM_Evasion (Rule 4) [Dynamic Obfuscated]", party_check))
                    stats["evasion_dynamic"] += 1
                else:
                    active_rules.append(("Evasion_with_Camouflage (Rule 4) [Disguised Tracker]", party_check))
                    stats["camouflaged_3rd_party"] += 1
            else:
                                                                                 
                is_dest_unresolved = (dest_url == "DYNAMIC_URL" or "{VAR}" in dest_url)
                label = "DOM_Evasion (Rule 4) [Dynamic Obfuscated]" if is_dest_unresolved else "DOM_Evasion (Rule 4)"
                active_rules.append((label, party_check))
                if is_dest_unresolved:
                    stats["evasion_dynamic"] += 1
                else:
                    stats["evasion_dom"] += 1

                                                                                 
                                                                         

                                                                          
                                                          

                                                                             
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

                                                                      
                                                                       
    isolated = detect_isolated_exfil(domain_name, routes)
    parasitic = detect_parasitic_branch(domain_name, routes)
    dual_finding = detect_dual_context(domain_name, routes)
    r3_matched = dual_finding["is_dual_context"]
    domain_context_map[domain_name].update({
        "r3_dual_context": r3_matched,
        "eligible_autonomous_route_count": len(dual_finding["autonomous_routes"]),
        "eligible_event_driven_route_count": len(dual_finding["event_driven_routes"]),
        "eligible_unknown_route_count": len(dual_finding["unknown_context_routes"]),
        "ineligible_route_count": len(dual_finding["ineligible_routes"]),
        "autonomous_evidence_route_ids": [
            r.get("route_id") for r in dual_finding["autonomous_routes"]
        ] if r3_matched else [],
        "event_driven_evidence_route_ids": [
            r.get("route_id") for r in dual_finding["event_driven_routes"]
        ] if r3_matched else [],
        "unknown_context_route_ids": [
            r.get("route_id") for r in dual_finding["unknown_context_routes"]
            if r.get("route_id") is not None
        ] if r3_matched else [],
        "ineligible_route_ids": [
            r.get("route_id") for r in dual_finding["ineligible_routes"]
            if r.get("route_id") is not None
        ],
    })
    semantic, fingerprint = detect_semantic_validation(domain_name, routes, domain_has_tracker)
    independent_rule_match = bool(
        domain_threats or isolated or parasitic or semantic or fingerprint
    )
    domain_context_map[domain_name]["independent_tracking_rule_match"] = (
        independent_rule_match
    )

    if independent_rule_match:
        is_malicious = True
        stats["total_malicious"] += 1
        malicious_records.extend(domain_threats)

                                           
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

                                                            
        for r in semantic:
            src       = r.get("source_name", "") or "Unknown"
            sink_name = r.get("sink_name", "")
            dest_url  = r.get("destination_url", "DYNAMIC_URL")
            tctx      = r.get("trigger_context", "UNKNOWN")
            is_domain_level = r.pop("_semantic_evidence", None) == "domain_level"
                                                                
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


                                                                                               
        if draw_graphs:
            print(f"    [🎨 Graphviz] Malicious domain visualization triggered: {domain_name}")
            viz_script = os.path.expanduser("~/mixed-hermes/build/bin/report/viz_tool7.py")
            try:
                subprocess.run(["python3", viz_script, str(file_path)], check=True)

                graph_dir = os.path.join(RESULT_DIR, "graphs")
                os.makedirs(graph_dir, exist_ok=True)

                                                             
                for graph_type in ["gtg", "ctg"]:
                    dot_file = str(file_path).replace(".json", f"_{graph_type}.dot")
                    png_file = os.path.join(graph_dir, f"{domain_name}_{graph_type}.png")
                    if os.path.exists(dot_file):
                        subprocess.run(["dot", "-Tpng", dot_file, "-o", png_file], check=True)
                        os.remove(dot_file)
                        print(f"    [🌟 Graph Saved] [{graph_type.upper()}] -> {png_file}")
            except Exception as e:
                print(f"    [❌ Graph Error] Visualization failed: {e}")


def is_corrected_r3(ctx):
    return (
        bool(ctx.get("r3_dual_context", False))
        and ctx.get("r3_context_basis") == "SINK_EXECUTION_CHAIN"
    )


def write_domain_findings():
    """Persist domain-scoped R3 findings separately from route verdicts."""
    findings = []
    for domain_name in sorted(domain_context_map):
        ctx = domain_context_map[domain_name]
        matched = bool(ctx.get("r3_dual_context", False))
        independent_match = bool(ctx.get("independent_tracking_rule_match", False))
        context_basis = ctx.get("r3_context_basis", "LEGACY_UNSPECIFIED")
        valid_for_corrected_headline = context_basis == "SINK_EXECUTION_CHAIN"
        if matched and not valid_for_corrected_headline:
            result_class = "R3_LEGACY_CONTEXT_REQUIRES_RERUN"
        elif matched and independent_match:
            result_class = "R3_WITH_INDEPENDENT_RULE_MATCH"
        elif matched:
            result_class = "STRUCTURAL_R3_ONLY_UNCONFIRMED"
        else:
            result_class = "NOT_R3"
        findings.append({
            "domain": domain_name,
            "report_id": domain_name,
            "rule": "R3",
            "scope": "DOMAIN",
            "context_basis": context_basis,
            "decision_expression": "AUTONOMOUS_ROUTE_COUNT>0 AND EVENT_DRIVEN_ROUTE_COUNT>0",
            "matched": matched,
            "valid_for_corrected_headline": valid_for_corrected_headline,
            "independent_tracking_rule_match": independent_match,
            "result_class": result_class,
            "autonomous_route_count": ctx.get("eligible_autonomous_route_count", 0),
            "event_driven_route_count": ctx.get("eligible_event_driven_route_count", 0),
            "unknown_route_count": ctx.get("eligible_unknown_route_count", 0),
            "ineligible_route_count": ctx.get("ineligible_route_count", 0),
            "autonomous_evidence_route_ids": ctx.get(
                "autonomous_evidence_route_ids", []
            ),
            "event_driven_evidence_route_ids": ctx.get(
                "event_driven_evidence_route_ids", []
            ),
            "unknown_context_route_ids": ctx.get(
                "unknown_context_route_ids", []
            ),
            "ineligible_route_ids": ctx.get("ineligible_route_ids", []),
            "event_driven_functions_diagnostic": ctx.get(
                "event_driven_functions", 0
            ),
        })

    with open(DOMAIN_FINDINGS_JSON, "w", encoding="utf-8") as output:
        json.dump(findings, output, indent=2, ensure_ascii=False)

    fieldnames = [
        "domain", "report_id", "rule", "scope", "context_basis",
        "decision_expression", "matched", "valid_for_corrected_headline",
        "independent_tracking_rule_match", "result_class",
        "autonomous_route_count", "event_driven_route_count",
        "unknown_route_count", "ineligible_route_count",
        "autonomous_evidence_route_ids",
        "event_driven_evidence_route_ids", "unknown_context_route_ids",
        "ineligible_route_ids", "event_driven_functions_diagnostic",
    ]
    with open(DOMAIN_FINDINGS_CSV, "w", newline="", encoding="utf-8-sig") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            row = dict(finding)
            for key in (
                "autonomous_evidence_route_ids",
                "event_driven_evidence_route_ids",
                "unknown_context_route_ids",
                "ineligible_route_ids",
            ):
                row[key] = json.dumps(row[key], separators=(",", ":"))
            writer.writerow(row)

    return findings

                                            
                  
                                            
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

    domain_findings = write_domain_findings()
    stats["dual_context"] = sum(
        1 for finding in domain_findings
        if finding["matched"] and finding["valid_for_corrected_headline"]
    )
    r3_with_independent_match = sum(
        1 for finding in domain_findings
        if finding["result_class"] == "R3_WITH_INDEPENDENT_RULE_MATCH"
    )
    structural_r3_only = sum(
        1 for finding in domain_findings
        if finding["result_class"] == "STRUCTURAL_R3_ONLY_UNCONFIRMED"
    )
    print(f" Domain-level R3 findings saved: {DOMAIN_FINDINGS_CSV}")
    print(f" Domain-level R3 JSON saved: {DOMAIN_FINDINGS_JSON}")

                                                                                 
    if malicious_records:
        RULE_ORDER = {
            "Isolated_Exfiltration (Rule 1)":                         1,
            "Parasitic_Branch (Rule 2)":                               2,
            "DOM_Evasion (Rule 4)":                                    4,
            "DOM_Evasion (Rule 4) [Dynamic Obfuscated]":                        4,
            "Evasion_with_Camouflage (Rule 4) [Disguised Tracker]":             4,
            "Semantic_CrossValidation (Rule 5) [Deterministic]":       5,
            "Semantic_CrossValidation (Rule 5) [Probabilistic]":       5,
            "Fingerprinting_Leak (Rule 5)":                            5,
        }

                                                                             
                                                               
                                                                           
                                                                            
        def _normalize_dest(dest: str) -> str:
            if not dest or dest == "DYNAMIC_URL": return "DYNAMIC_URL"
            if "{VAR}" in dest: return "DYNAMIC_URL"
            if "Predicted" in dest or "Hybrid Reconstructed" in dest or "CNAME Cloaked" in dest:
                return "DYNAMIC_URL"
            return dest

        dedup: dict = {}                        
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
                
                                                                                                                                                       
                _labels_now = [l.strip() for l in dedup[key]["Threat_Type"].split(" | ")]
                if "DOM_Evasion (Rule 4)" in _labels_now and "DOM_Evasion (Rule 4) [Dynamic Obfuscated]" in _labels_now:
                    _labels_now = sorted(set(l for l in _labels_now if l != "DOM_Evasion (Rule 4) [Dynamic Obfuscated]"))
                    dedup[key]["Threat_Type"] = " | ".join(_labels_now)

                                                                                                 
                if dedup[key]["Destination"] == "DYNAMIC_URL" and rec.get("Destination", "") != "DYNAMIC_URL":
                    dedup[key]["Destination"] = rec.get("Destination", "DYNAMIC_URL")
                                                                                                                                  
                    new_party = determine_unified_party(dedup[key]["Domain"], dedup[key]["Destination"], dedup[key]["Leak_Method (Sink)"])
                    if "WCC Isolated" not in dedup[key]["Party_Check"] and "Confirmed 3rd-Party" not in dedup[key]["Party_Check"]:
                        dedup[key]["Party_Check"] = new_party

        deduped = list(dedup.values())

                                                                           
        def sort_key(rec):
            labels = rec.get("Threat_Type", "").split(" | ")
            min_rule = min(RULE_ORDER.get(lbl, 99) for lbl in labels)
            return (min_rule, rec.get("Domain", ""))

        deduped.sort(key=sort_key)

                                                                            
                                                             
                                              
                                    
                                                                               
        def compute_confidence(rec: dict) -> int:
            score = 0
            labels = [l.strip() for l in rec.get("Threat_Type", "").split(" | ")]
            rule_nums = {RULE_ORDER.get(l, 99) for l in labels if RULE_ORDER.get(l, 99) != 99}
            score += min(len(rule_nums), 3)                                         
            if rec.get("Trigger_Context") == "AUTONOMOUS":
                score += 1                                                        
            dest = rec.get("Destination", "")
            if "Predicted 3rd-Party" in dest or "Hybrid Reconstructed" in dest or "CNAME Cloaked" in dest:
                score += 1                                                        
            return max(1, min(score, 5))                            

        for rec in deduped:
            rec["Confidence_Score"] = compute_confidence(rec)

                                                                             
                                                                                  
                                                                                    
                                                                                      
        for rec in deduped:
            threat = rec.get("Threat_Type", "")
            dest   = rec.get("Destination", "")
            if "Isolated_Exfiltration (Rule 1)" in threat and "WCC Isolated" in rec.get("Party_Check", ""):
                                                                                                                           
                if "CNAME Cloaked" in dest:
                    rec["Party_Check"] = "1st-Party (CNAME Cloaked)"
                elif "Hybrid Reconstructed" in dest and "1st-Party" in determine_unified_party(rec["Domain"], dest, rec["Leak_Method (Sink)"]):
                    rec["Party_Check"] = "1st-Party (Hybrid)"
                elif ("Semantic_CrossValidation (Rule 5)" in threat or
                        "Predicted 3rd-Party" in dest or
                        "Hybrid Reconstructed" in dest):
                    rec["Party_Check"] = "3rd-Party (WCC Isolated)"

                                                                             
                                                                  
                                                               
        final_stats = {
            "total_scanned":       stats["total_scanned"],
            "total_malicious":     len({rec["Domain"] for rec in deduped}),
            "isolated_exfil":      0,
            "parasitic_branch":    0,
            "dual_context":        stats["dual_context"],
            "evasion_dom":         0,
            "evasion_dynamic":     0,
            "fingerprinting":      0,
            "semantic_crossval":   0,
            "camouflaged_3rd_party": 0,
        }
        LABEL_TO_STAT = {
            "Isolated_Exfiltration (Rule 1)":                         "isolated_exfil",
            "Parasitic_Branch (Rule 2)":                               "parasitic_branch",
            "DOM_Evasion (Rule 4)":                                    "evasion_dom",
            "DOM_Evasion (Rule 4) [Dynamic Obfuscated]":                        "evasion_dynamic",
            "Evasion_with_Camouflage (Rule 4) [Disguised Tracker]":             "camouflaged_3rd_party",
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
            writer.writerow(["Dual Execution Context (Rule 3)",          f"{final_stats['dual_context']} unique domains"])
            writer.writerow(["  ├ R3 with independent rule match",       f"{r3_with_independent_match} unique domains"])
            writer.writerow(["  └ Structural R3 Only (Unconfirmed)",     f"{structural_r3_only} unique domains"])
            writer.writerow(["DOM Evasion (Rule 4)",                     f"{final_stats['evasion_dom'] + final_stats['evasion_dynamic']} cases"])
            writer.writerow(["  └ Destination Identified",                 f"{final_stats['evasion_dom']} cases"])
            writer.writerow(["  └ Destination Hidden (Dynamic Obfuscated)", f"{final_stats['evasion_dynamic']} cases"])
            writer.writerow(["Semantic Cross-Validation (Rule 5)",       f"{final_stats['semantic_crossval']} cases"])
            writer.writerow(["  └ [Deterministic] URL confirmed tracker",    f"{sum(1 for r in deduped if 'Deterministic' in r.get('Threat_Type',''))} cases"])
            writer.writerow(["  └ [Probabilistic] Domain-inferred tracker",  f"{sum(1 for r in deduped if 'Probabilistic' in r.get('Threat_Type',''))} cases"])
            writer.writerow(["  └ Fingerprinting Leak (Rule 5 sub-case)",     f"{final_stats['fingerprinting']} cases"])
            writer.writerow(["Camouflaged 3rd-party leak",                f"{final_stats['camouflaged_3rd_party']} cases (Core finding!)"])

                                                        
            writer.writerow([])
            writer.writerow(["[Per-Domain Mixed Tracker Evidence]"])
                                              
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
                if is_corrected_r3(domain_context_map[dom]):
                    rules_hit = sorted(set(rules_hit) | {3})
                rules_str = ",".join(f"R{r}" for r in rules_hit) if rules_hit else "None"
                is_dual = is_corrected_r3(ctx)
                ctx_label = "Mixed (Dual Context)" if is_dual else "Single Context"
                writer.writerow([f"  {dom}", f"Routes: AUTONOMOUS={auto} EVENT_DRIVEN={event} | Handlers={ed_funcs} ({ctx_label})", f"Rules: {rules_str}"])

                                                                             
        if args.summary:
            summary_path = CSV_OUTPUT.replace(".csv", "_summary.csv")
            domain_summary: dict = {
                dom: {
                    "Domain": dom,
                    "Rule_1": 0, "Rule_2": 0, "Rule_3": 0,
                    "Rule_4": 0, "Rule_5": 0,
                    "Total_Routes": 0,
                    "Max_Confidence": 0,
                    "3rd_Party_Confirmed": 0,
                }
                for dom in domain_context_map
            }
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

            for dom, entry in domain_summary.items():
                if is_corrected_r3(domain_context_map.get(dom, {})):
                    entry["Rule_3"] = 1

            summary_rows = sorted(domain_summary.values(), key=lambda r: -r["Total_Routes"])
            with open(summary_path, 'w', newline='', encoding='utf-8-sig') as sf:
                sw = csv.DictWriter(sf, fieldnames=["Domain","Rule_1","Rule_2","Rule_3","Rule_4","Rule_5","Total_Routes","Max_Confidence","3rd_Party_Confirmed"])
                sw.writeheader()
                sw.writerows(summary_rows)
            print(f" Per-domain summary saved: {summary_path}")


                                                                                                  
    _s = final_stats if malicious_records else stats
    print(" Analysis Complete! [Final Statistical Report]")
    print(f"- Total domains scanned : {_s['total_scanned']}")
    print(f"- Malicious tracker infected domains : {_s['total_malicious']}\n")
    print("[Detailed Evasion Technique Statistics]")
    print(f"  > Isolated Exfiltration (Rule 1)        : {_s['isolated_exfil']} cases")
    print(f"  > Parasitic Branch (Rule 2)             : {_s['parasitic_branch']} cases")
    print(f"  > Dual Execution Context (Rule 3)       : {_s['dual_context']} unique domains")
    print(f"  >   ├ R3 with independent rule match   : {r3_with_independent_match} unique domains")
    print(f"  >   └ Structural R3 Only (Unconfirmed) : {structural_r3_only} unique domains")
    print(f"  > DOM Evasion (Rule 4)                  : {_s['evasion_dom'] + _s['evasion_dynamic']} cases")
    print(f"  >   └ Destination Identified             : {_s['evasion_dom']} cases")
    print(f"  >   └ Destination Hidden (Dyn. Obfusc.) : {_s['evasion_dynamic']} cases")
    print(f"  > Semantic Cross-Validation (Rule 5)    : {_s['semantic_crossval']} cases")
    print(f"  >   └ Fingerprinting Leak (sub-case)    : {_s['fingerprinting']} cases")
    print(f"  > Camouflaged 3rd-party leak            : {_s['camouflaged_3rd_party']} cases (Core finding!)")
    print("==================================================")
    print(f" Detailed malicious domain blacklist saved as CSV: {CSV_OUTPUT}")
