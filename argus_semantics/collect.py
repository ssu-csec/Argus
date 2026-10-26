"""Compile only (never execute corpus JS) and retain endpoint-bearing raw IR."""
import argparse
import concurrent.futures
import csv
import hashlib
import importlib.util
import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def select_functions(lines, locations):
    buf, keep = [], False
    for line in lines:
        if re.match(r'^(function|arrow|generator) ', line):
            buf, keep = [line], False
        elif buf:
            buf.append(line)
            m = re.match(r'; .*:(\d+):(\d+)\s*$', line)
            if m and (int(m[1]), int(m[2])) in locations:
                keep = True
            if line.startswith('function_end'):
                if keep:
                    yield ''.join(buf)
                buf = []

def collect_one(domain, ids, manifest, reports, out, engine):
    dest = out / 'ir' / domain
    dest.mkdir(parents=True, exist_ok=True)
    meta = {'domain': domain, 'engine_sha256': sha(engine), 'mode': 'compile_only_auditor',
            'preprocessor_sha256': sha(ROOT/'results/run_smoke_manifest.py')}
    try:
        report = json.loads((reports / f'{domain}_report.json').read_text())
        routes = [r for r in report['s2s_routes'] if str(r['route_id']) in ids]
        if len(routes) != len(ids):
            raise ValueError('missing/duplicate historical route IDs')
        source = Path(manifest['wholepage_path'])
        meta['original_sha256'] = sha(source)
        if meta['original_sha256'] != manifest['sha256']:
            raise ValueError('original manifest hash mismatch')
        spec = importlib.util.spec_from_file_location('preprocessor', ROOT/'results/run_smoke_manifest.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        prepared = runner.preprocess_js(source, domain, out/'reconstructed')
        meta['reconstructed_sha256'] = sha(prepared)
        byte_lines = prepared.read_bytes().split(b'\n')
        for r in routes:
            for side in ('source','sink'):
                loc = r[side+'_location']; start = loc['snippet_start_column']-1
                snippet = (byte_lines[loc['line']-1]+b'\n')[start:start+240].decode('utf-8',errors='replace')
                if snippet != loc['snippet']:
                    raise ValueError(f'location snippet mismatch: {r["route_id"]} {side}')
        locations = {(r[s+'_location']['line'],r[s+'_location']['column']) for r in routes for s in ('source','sink')}
                                                                       
        old = dest/'metadata.json'
        if old.exists() and (dest/'functions.ir').exists():
            cached = json.loads(old.read_text())
            if cached.get('status') == 'OK' and all(cached.get(k)==v for k,v in meta.items()) and cached.get('route_ids')==sorted(ids):
                return domain, 'CACHED'
        cmd = [str(engine),'-O0','-custom-opt=auditor','-w','-dump-ir','-dump-source-location=loc',str(prepared)]
        meta.update(command=cmd, route_ids=sorted(ids))
        with tempfile.TemporaryFile(mode='w+t') as raw, (dest/'stderr.log').open('w') as err:
            run = subprocess.run(cmd,cwd=dest,stdout=raw,stderr=err,timeout=120)
            if run.returncode:
                raise ValueError(f'compiler exit {run.returncode}')
            raw.seek(0)
            with (dest/'functions.ir').open('w') as f:
                for block in select_functions(raw,locations): f.write(block+'\n')
        (dest/'routes.json').write_text(json.dumps(routes,ensure_ascii=False,indent=2))
        meta['status']='OK'
        meta['ir_sha256']=sha(dest/'functions.ir')
    except Exception as exc:
        meta.update(status='UNAVAILABLE',error=f'{type(exc).__name__}: {exc}')
    (dest/'metadata.json').write_text(json.dumps(meta,indent=2))
    return domain,meta['status']

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sample',type=Path,required=True)
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--reports',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--engine',type=Path,default=ROOT/'build/bin/mixed-hermes')
    p.add_argument('--workers',type=int,default=2)
    a=p.parse_args();a.out=a.out.resolve();a.engine=a.engine.resolve()
    with a.sample.open(encoding='utf-8-sig') as f: rows=list(csv.DictReader(f))
    with a.manifest.open(encoding='utf-8-sig') as f: manifest={r['domain']:r for r in csv.DictReader(f)}
    grouped={}
    for r in rows:grouped.setdefault(r['domain'],set()).add(r['route_id'])
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures=[pool.submit(collect_one,d,ids,manifest[d],a.reports,a.out,a.engine) for d,ids in grouped.items()]
        for i,f in enumerate(concurrent.futures.as_completed(futures),1):
            print(i,len(futures),*f.result(),flush=True)

if __name__=='__main__': main()
