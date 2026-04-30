import json
import os
import sys
import hashlib

GRAPH_HEADER = [
    '    rankdir=TB;',
    '    node [fontname="Arial", fontsize=11];',
    '    edge [fontname="Arial", fontsize=9];',
    '    subgraph cluster_legend {',
    '        label="Legend (Hybrid Forensic View)"; style=dotted; color=gray;',
    '        "L_Source"       [label="Source",        fillcolor="#f9f9ff", style=filled,        shape=ellipse];',
    '        "L_DynSource"    [label="Dynamic_Source", fillcolor="#e0e0e0", style="filled,dashed", shape=ellipse, fontcolor="#555555"];',
    '        "L_IRInst"       [label="Hermes IR Inst", fillcolor="#fffbd9", style=filled,        shape=box,    color="#d4c63b"];',
    '        "L_JSCall"       [label="JS Function Call",fillcolor="#ffe0b2", style=filled,       shape=box,    color="#f57c00"];',
    '        "L_Sink"         [label="Sink",           fillcolor="#ccffcc", style=filled,        shape=box3d];',
    '    }',
]

def _node_id(label):
    """Stable short node id from a label string (safe for dot syntax)."""
    return "N_" + hashlib.md5(label.encode()).hexdigest()[:10]

def _src_attrs(src_label):
    if not src_label or src_label in ("Unknown", ""):
        return ('[Dynamic_Source]',
                'fillcolor="#e0e0e0", fontcolor="#555555", style="filled,dashed", shape=ellipse, penwidth=2')
    return (src_label,
            'fillcolor="#f9f9ff", style=filled, shape=ellipse, penwidth=2')

def _sink_attrs(sink_label):
    if "Unknown" in sink_label:
        return 'fillcolor="#ffcccc", style=filled, shape=box3d, color="red", penwidth=2'
    return 'fillcolor="#ccffcc", style=filled, shape=box3d, penwidth=2'

def _generate_gtg(routes):
    """
    Global Taint Graph: shared Source / Sink nodes, edges deduplicated.
    Same source or same sink reuses the same graph node.
    """
    declared = set()
    edges    = set()
    lines    = ['digraph Hephaistos_GTG {'] + GRAPH_HEADER

    total_edges = 0

    for route in routes:
        src_raw  = route.get("source_name", "").strip()
        sink_raw = route.get("sink_name", "Unknown").strip()
        dest     = route.get("destination_url", "Unknown").strip().replace('"', "'")
        nodes    = route.get("path_nodes", [])

        display_src, src_attrs = _src_attrs(src_raw)
        sink_attrs = _sink_attrs(sink_raw)

        src_id = _node_id(display_src)
        if src_id not in declared:
            lines.append(f'    "{src_id}" [label="{display_src}", {src_attrs}];')
            declared.add(src_id)

        sink_key = f"{sink_raw}\n{dest}"
        sink_id  = _node_id(sink_key)
        sink_label = f"{sink_raw}\\n{dest}" if dest != "Unknown" else sink_raw
        if sink_id not in declared:
            lines.append(f'    "{sink_id}" [label="{sink_label}", {sink_attrs}];')
            declared.add(sink_id)

        prev_id = src_id
        rid = route.get("route_id", 0)
        for i, inst in enumerate(nodes):
            inst_id = _node_id(f"{rid}_{i}_{inst}")
            if "CallInst" in inst:
                attrs = 'label="CallInst\\n(JS API)", fillcolor="#ffe0b2", style=filled, shape=box, color="#f57c00", penwidth=1.8'
            else:
                attrs = f'label="{inst}", fillcolor="#fffbd9", style=filled, shape=box, color="#d4c63b"'
            if inst_id not in declared:
                lines.append(f'    "{inst_id}" [{attrs}];')
                declared.add(inst_id)
            edge = (prev_id, inst_id)
            if edge not in edges:
                lines.append(f'    "{prev_id}" -> "{inst_id}" [color="#d32f2f", penwidth=2.5];')
                edges.add(edge); total_edges += 1
            prev_id = inst_id

        edge = (prev_id, sink_id)
        if edge not in edges:
            lines.append(f'    "{prev_id}" -> "{sink_id}" [color="#d32f2f", penwidth=2.5];')
            edges.add(edge); total_edges += 1

    lines.append('}')
    return lines, total_edges

def _filter_threat_routes(routes):
    """
    CTG: keep only routes where the destination was successfully resolved
    by hybrid analysis (not DYNAMIC_URL).
    GTG = all taint paths (every attempt).
    CTG = confirmed exfiltration paths (where data actually went).
    """
    resolved = [r for r in routes if r.get("destination_url", "") != "DYNAMIC_URL"]
    return resolved if resolved else routes


def _generate_ctg(routes):
    """
    Core Taint Graph: all confirmed threat paths with shared Source/Sink nodes.
    Same structure as GTG but filtered to only exfiltration-risk routes.
    """
    threat_routes = _filter_threat_routes(routes)
    lines = ['digraph Hephaistos_CTG {'] + GRAPH_HEADER

    declared = set()
    edges    = set()
    total_edges = 0

    for route in threat_routes:
        src_raw  = route.get("source_name", "").strip()
        sink_raw = route.get("sink_name", "Unknown").strip()
        dest     = route.get("destination_url", "Unknown").strip().replace('"', "'")
        nodes    = route.get("path_nodes", [])
        rid      = route.get("route_id", 0)

        display_src, src_attrs = _src_attrs(src_raw)
        sink_attrs = _sink_attrs(sink_raw)

        src_id = _node_id(display_src)
        if src_id not in declared:
            lines.append(f'    "{src_id}" [label="{display_src}", {src_attrs}];')
            declared.add(src_id)

        sink_key   = f"{sink_raw}\n{dest}"
        sink_id    = _node_id(sink_key)
        sink_label = f"{sink_raw}\\n{dest}" if dest != "Unknown" else sink_raw
        if sink_id not in declared:
            lines.append(f'    "{sink_id}" [label="{sink_label}", {sink_attrs}];')
            declared.add(sink_id)

        prev_id = src_id
        for i, inst in enumerate(nodes):
            inst_id = _node_id(f"{rid}_{i}_{inst}")
            if "CallInst" in inst:
                attrs = 'label="CallInst\\n(JS API)", fillcolor="#ffe0b2", style=filled, shape=box, color="#f57c00", penwidth=1.8'
            else:
                attrs = f'label="{inst}", fillcolor="#fffbd9", style=filled, shape=box, color="#d4c63b"'
            if inst_id not in declared:
                lines.append(f'    "{inst_id}" [{attrs}];')
                declared.add(inst_id)
            edge = (prev_id, inst_id)
            if edge not in edges:
                lines.append(f'    "{prev_id}" -> "{inst_id}" [color="#d32f2f", penwidth=2.5];')
                edges.add(edge); total_edges += 1
            prev_id = inst_id

        edge = (prev_id, sink_id)
        if edge not in edges:
            lines.append(f'    "{prev_id}" -> "{sink_id}" [color="#d32f2f", penwidth=2.5];')
            edges.add(edge); total_edges += 1

    lines.append('}')
    return lines, total_edges, len(threat_routes)

def generate_graphs(report_file):
    print(f" [Analyzing] Reading JSON report: {report_file}")

    base    = os.path.splitext(report_file)[0]
    gtg_dot = f"{base}_gtg.dot"
    ctg_dot = f"{base}_ctg.dot"

    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f" Failed to parse JSON: {e}"); return None, None

    routes = data.get("s2s_routes", [])
    if not routes:
        print("  Warning: No 's2s_routes' found."); return None, None

    gtg_lines, gtg_edges = _generate_gtg(routes)
    with open(gtg_dot, 'w', encoding='utf-8') as f:
        f.write("\n".join(gtg_lines))
    print(f"\n - GTG complete: {gtg_dot}")
    print(f"   Routes: {len(routes)}  |  Edges: {gtg_edges}")

    ctg_lines, ctg_edges, ctg_count = _generate_ctg(routes)
    with open(ctg_dot, 'w', encoding='utf-8') as f:
        f.write("\n".join(ctg_lines))
    print(f"\n - CTG complete: {ctg_dot}")
    print(f"   Threat Routes: {ctg_count}  |  Edges: {ctg_edges}")

    return gtg_dot, ctg_dot


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 viz_tool7.py <report_file.json>")
    else:
        generate_graphs(sys.argv[1])