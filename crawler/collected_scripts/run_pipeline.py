import os
import re
import subprocess
import shutil
import tempfile
import time
from pathlib import Path

ENGINE_PATH = os.path.expanduser("~/argus/build/bin/mixed-hermes")
CRAWLER_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_DIR  = os.path.expanduser("~/argus/pipeline_results")
REPORT_DIR  = os.path.abspath("report")

os.makedirs(RESULT_DIR, exist_ok=True)


def fmt_time(seconds):
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    if h > 0:
        return f"{h}h {m}m {s}s"
    elif m > 0:
        return f"{m}m {s}s"
    else:
        return f"{s}s"


def print_progress(idx, total, start_time, domain_name):
    elapsed   = time.time() - start_time
    pct       = idx / total * 100
    speed     = idx / elapsed * 60 if elapsed > 0 else 0
    remaining = (total - idx) / (idx / elapsed) if idx > 0 else 0
    bar_len   = 25
    filled    = int(bar_len * idx // total)
    bar       = '█' * filled + '░' * (bar_len - filled)
    print(
        f"[{bar}] {idx:>4}/{total} ({pct:5.1f}%)  "
        f"elapsed {fmt_time(elapsed)}  "
        f"ETA {fmt_time(remaining)}  "
        f"{speed:.1f} dom/min  "
        f"-> {domain_name}",
        flush=True
    )


def preprocess_js(js_path_str):
    FILE_HEADER = "// [FILE] Source:"
    SEPARATOR   = "// ==========================================\n"
    try:
        with open(js_path_str, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        content = content.replace('\x00', '_')
        content = content.replace('\\u0000', '_')
        content = content.replace('\ufffd', '_')
        content = re.sub(r'[\U00010000-\U0010ffff]', '_', content)

        if FILE_HEADER in content:
            split_marker = SEPARATOR + FILE_HEADER
            parts = content.split(split_marker)
            wrapped_parts = []
            for i, part in enumerate(parts):
                if i == 0:
                    if part.strip():
                        wrapped_parts.append(f';(function(){{try{{\n{part}\n}}catch(e){{}}}})()')
                else:
                    newline_pos = part.find('\n')
                    source_url  = part[:newline_pos].strip()
                    code_body   = part[newline_pos:]
                    wrapped_parts.append(
                        f'{SEPARATOR}{FILE_HEADER}{source_url}\n'
                        f'{SEPARATOR}'
                        f';(function(){{try{{\n{code_body}\n}}catch(e){{}}}})()')
            content = '\n'.join(wrapped_parts)

        tmp = tempfile.NamedTemporaryFile(
            suffix='_pre.js',
            dir=os.path.dirname(js_path_str),
            delete=False, mode='w', encoding='utf-8'
        )
        tmp.write(content)
        tmp.close()
        return tmp.name, True
    except Exception:
        return js_path_str, False


def process_file(js_path_obj):
    domain_name = js_path_obj.parent.name
    js_file_str = str(js_path_obj)

    js_to_analyze, was_preprocessed = preprocess_js(js_file_str)
    cmd = [ENGINE_PATH, "-O", js_to_analyze]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=300
        )

        engine_report   = os.path.join(REPORT_DIR, f"{domain_name}_report.json")
        fallback_report = os.path.join(REPORT_DIR, "report.json")

        if os.path.exists(engine_report):
            shutil.move(engine_report, os.path.join(RESULT_DIR, f"{domain_name}_report.json"))
            return "SUCCESS"
        elif os.path.exists(fallback_report):
            shutil.move(fallback_report, os.path.join(RESULT_DIR, f"{domain_name}_report.json"))
            return "SUCCESS (fallback)"
        else:
            if proc.returncode == 0:
                return "FAILED (No taint path found -- clean exit)"
            err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
            import re as _re
            errors = _re.findall(r'error: ([^\n]+)', err_msg)
            key_errors = list(dict.fromkeys(
                e.strip()[:80] for e in errors
                if e.strip() and not e.strip().startswith('~') and len(e.strip()) > 3
            ))[:2]
            snippet = ' / '.join(key_errors) if key_errors else '(no message)'
            if proc.returncode == 2 and ("errors emitted" in err_msg or "error:" in err_msg):
                return f"PARSE ERROR -> {snippet}"
            return f"ENGINE CRASH (exit={proc.returncode}) -> {snippet}"

    except subprocess.TimeoutExpired:
        return "TIMEOUT (>300s)"
    except Exception as e:
        return f"ERROR: {e}"
    finally:
        if was_preprocessed:
            try:
                os.unlink(js_to_analyze)
            except OSError:
                pass


if __name__ == "__main__":
    print("==================================================")
    print("Argus Large-Scale Mixed Tracker Analysis Pipeline Started")
    print("==================================================")

    crawler_path = Path(CRAWLER_DIR)
    if not crawler_path.exists():
        print(f"[!] Crawler data folder not found: {CRAWLER_DIR}")
        exit(1)

    target_files = list(crawler_path.rglob("wholepage.js"))
    print(f"Found {len(target_files)} 'wholepage.js' files in total!\n")

    analyzed_domains = set()
    if os.path.exists(RESULT_DIR):
        for f in os.listdir(RESULT_DIR):
            if f.endswith("_report.json"):
                analyzed_domains.add(f.replace("_report.json", ""))

    TRANCO_LIMIT = 100000
    tranco_path  = os.path.join(CRAWLER_DIR, "tranco-1M.txt")
    top_domains  = set()

    if os.path.exists(tranco_path):
        with open(tranco_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= TRANCO_LIMIT:
                    break
                top_domains.add(line.strip())
        print(f"Loaded {len(top_domains)} top domains from Tranco-1M.")
    else:
        print(f"[!] Warning: Tranco list not found at {tranco_path}, analyzing all.")

    remaining_files    = []
    skipped_by_tranco  = 0
    for js_path in target_files:
        domain = js_path.parent.name
        if top_domains and domain not in top_domains:
            skipped_by_tranco += 1
            continue
        if domain not in analyzed_domains:
            remaining_files.append(js_path)

    print(f"Skipping {skipped_by_tranco} domains not in Tranco Top 100K.")
    print(f"Skipping {len(target_files) - len(remaining_files) - skipped_by_tranco} already analyzed domains.")
    print(f"Starting analysis for {len(remaining_files)} domains...\n")

    start_time = time.time()
    total      = len(remaining_files)
    success    = 0
    clean      = 0
    parse_err  = 0
    crashed    = 0
    timeout    = 0

    import csv, datetime
    log_path = os.path.join(
        RESULT_DIR,
        f"failed_domains_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )
    log_file   = open(log_path, 'w', newline='', encoding='utf-8')
    log_writer = csv.writer(log_file)
    log_writer.writerow(['domain', 'status', 'reason'])

    print(f"{'─'*60}")
    print(f"  Total targets  : {total} domains")
    print(f"  Output dir     : {RESULT_DIR}")
    print(f"  Failure log    : {log_path}")
    print(f"{'─'*60}\n")

    for idx, js_path in enumerate(remaining_files, start=1):
        domain_name = js_path.parent.name
        print_progress(idx, total, start_time, domain_name)
        result = process_file(js_path)
        print(f"    └─ {result}")

        if "SUCCESS" in result:
            success += 1
        else:
            if "TIMEOUT" in result:
                timeout += 1
                status = "TIMEOUT"
            elif "No taint path" in result:
                clean += 1
                status = "NO_TAINT"
            elif "PARSE ERROR" in result:
                parse_err += 1
                status = "PARSE_ERROR"
            else:
                crashed += 1
                status = "ENGINE_CRASH"
            reason = result.split('→')[-1].strip() if '→' in result else result
            log_writer.writerow([domain_name, status, reason])
            log_file.flush()

    log_file.close()
    total_elapsed = time.time() - start_time

    print(f"\n{'='*60}")
    print(f"Pipeline analysis complete!")
    print(f"{'─'*60}")
    print(f"  Success      : {success:>5} domains  (taint report generated)")
    print(f"  Clean        : {clean:>5} domains  (clean exit, no taint path)")
    print(f"  Parse error  : {parse_err:>5} domains  (unsupported JS syntax)")
    print(f"  Engine crash : {crashed:>5} domains  (abnormal exit)")
    print(f"  Timeout      : {timeout:>5} domains")
    print(f"{'─'*60}")
    print(f"  Total time   : {fmt_time(total_elapsed)}")
    avg_speed = total / (total_elapsed / 60) if total_elapsed > 0 else 0
    print(f"  Avg speed    : {avg_speed:.1f} domains/min")
    print(f"  Results      : {RESULT_DIR}")
    print(f"  Failure log  : {log_path}")
    print(f"{'='*60}")
