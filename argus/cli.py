"""Portable entry point. Source JS is compiled, never executed by analysis commands."""
import argparse, concurrent.futures, csv, gzip, hashlib, json, os, re, shutil, subprocess, sys, time
from pathlib import Path
from argus_pipeline.support import item_worker as bounded, stream_reader, transport, gate, semantic_guard

ROOT = Path(__file__).resolve().parents[1]
SUPPORT = ROOT/'argus_pipeline/support'
FLAGS = ['-O0','-Xes6-class','--block-scoping','--enable-tdz','-custom-opt=taintanalysis','-custom-opt=auditor','-w','-dump-ir','-dump-source-location=loc']
LIMITS = dict(memory_gib=8,file_limit_mib=256,item_limit_mib=1024,reserve_disk_gib=20)
FIELDS = ['Domain','Threat_Type','Trigger_Context','Leaked_Data (Source)','Leak_Method (Sink)','Destination','Observed_Trackers','Party_Check','Confidence_Score']
sha = bounded.sha

def put(path, value):
    Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def new_dir(path):
    path=Path(path).resolve();path.parent.mkdir(parents=True,exist_ok=True);path.mkdir(exist_ok=False)
    return path

def output_disk_free(path):
    ancestor=Path(path).resolve().parent
    while not ancestor.exists():
        ancestor=ancestor.parent
    return shutil.disk_usage(ancestor).free

def domain_name(value):
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?',value) or '..' in value:
        raise ValueError('Invalid domain key: '+value)
    value=value.lower().rstrip('.')
    if any(x in value for x in ('_report.json','_log.json')):raise ValueError('Ambiguous domain key')
    return value

def read_network(path):
    if path is None:return []
    data=json.loads(Path(path).read_text(encoding='utf-8'))
    if isinstance(data,list):
        if not all(isinstance(x,str) for x in data):raise ValueError('Network log must be a list of URLs')
        return sorted(set(x for x in data if x.startswith(('http://','https://'))))
    if isinstance(data,dict) and isinstance(data.get('requests'),list):
        return sorted({r['url'] for r in data['requests'] if isinstance(r.get('url'),str) and r['url'].startswith(('http://','https://')) and (r.get('response_received_at') or r.get('finished_at')) and r.get('collector_action')!='ABORT_RESOURCE_POLICY'})
    raise ValueError('Unsupported network log schema')

def normalize_jobs(items, base):
    jobs=[];seen=set()
    for item in items:
        domain=domain_name(item['domain'])
        if domain in seen:raise ValueError('Duplicate domain: '+domain)
        seen.add(domain)
        source=(base/Path(item['input'])).resolve()
        if not source.is_file():raise ValueError('Missing input: '+str(source))
        digest=sha(source)
        if item.get('sha256') and item['sha256']!=digest:raise ValueError('Input hash mismatch: '+domain)
        net=(base/Path(item['network_log'])).resolve() if item.get('network_log') else None
        jobs.append(dict(domain=domain,source=str(source),sha256=digest,network_urls=read_network(net),network_log=str(net) if net else None,network_sha256=sha(net) if net else None))
    if not jobs:raise ValueError('No analyzable inputs')
    return jobs

def crawl_jobs(root):
    items=[]
    for path in sorted(Path(root).glob('visits/*/visit.json')):
        v=json.loads(path.read_text());whole=v.get('wholepage') or {}
        if not whole.get('file'):continue
        source=(path.parent/whole['file']).resolve()
        if not source.is_relative_to(path.parent.resolve()):raise ValueError('Wholepage path escapes visit')
        items.append(dict(domain=v.get('hostname') or v.get('domain') or v.get('target',{}).get('hostname'),input=str(source),sha256=whole['sha256'],network_log=str(path.resolve())))
    return normalize_jobs(items,Path.cwd())

def classify_records(records,out,timeout=90):
    """Run frozen classifier in chunks with isolated HOME; export uniform CSV tables."""
    records=[dict(r,domain=domain_name(r['domain']))for r in records]
    if len({r['domain']for r in records})!=len(records):raise ValueError('Duplicate classification domain')
    out=new_dir(out);seen=set();all_findings=[];domain_findings=[]
    frozen=sha(ROOT/'classifier.py')
    for index in range(0,len(records),100):
        chunk=out/'chunks'/f'{index//100:05d}';chunk.mkdir(parents=True)
        home=chunk/'home';legacy=home/'mixed-hermes';reports=legacy/'pipeline_results';reports.mkdir(parents=True)
        pins=[]
        for r in records[index:index+100]:
            domain=domain_name(r['domain'])
            if domain in seen:raise ValueError('Duplicate classification domain: '+domain)
            seen.add(domain);source=Path(r['report']).resolve();digest=sha(source)
            if r.get('report_sha256') and digest!=r['report_sha256']:raise ValueError('Report hash mismatch')
            pins.append((source,digest));(reports/(domain+'_report.json')).symlink_to(source)
            network=legacy/'crawler/collected_scripts'/domain;network.mkdir(parents=True)
            put(network/'network_logs.json',r.get('network_urls',[]))
        env=dict(os.environ,HOME=str(home),PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8')
        ex=bounded.child([sys.executable,'-B',ROOT/'classifier.py','--summary'],chunk,chunk/'logs',timeout,LIMITS,env,chunk,lambda _:None)
        put(chunk/'execution.json',ex)
        if ex['returncode']!=0 or ex['stop_reason'] or ex['error']:raise RuntimeError('Rule classification failed; see '+str(chunk/'execution.json'))
        if not all(sha(p)==h for p,h in pins) or sha(ROOT/'classifier.py')!=frozen:raise RuntimeError('Classification source changed')
        outputs=legacy/'csv_reports';df=list(outputs.glob('domain_findings_*.json'))
        if len(df)!=1:raise RuntimeError('Missing domain findings')
        rows=json.loads(df[0].read_text())
        if {x['domain']for x in rows}!={r['domain']for r in records[index:index+100]}:raise RuntimeError('Domain coverage mismatch')
        domain_findings.extend(rows)
        for path in outputs.glob('malicious_domains_*.csv'):
            if path.name.endswith('_summary.csv'):continue
            with path.open(encoding='utf-8-sig',newline='')as stream:
                for row in csv.DictReader(stream):
                    if not row.get('Domain') or row['Domain'].startswith('==='):break
                    all_findings.append(row)
    with (out/'argus_findings.csv').open('w',encoding='utf-8-sig',newline='')as f:
        w=csv.DictWriter(f,fieldnames=FIELDS);w.writeheader();w.writerows(all_findings)
    grouped={r['domain']:[]for r in records}
    for f in all_findings:grouped[f['Domain']].append(f)
    bydomain={d['domain']:d for d in domain_findings};summaries=[]
    for domain,findings in sorted(grouped.items()):
        rules={int(n)for f in findings for n in re.findall(r'Rule ([1245])',f['Threat_Type'])}
        df=bydomain[domain]
        if df['matched']and df['valid_for_corrected_headline']:rules.add(3)
        summaries.append(dict(Domain=domain,Rules='+'.join('R'+str(n)for n in sorted(rules)),Finding_Groups=len(findings),Independent_Rule_Match=int(bool(findings)),R3_Class=df['result_class']))
    with (out/'argus_domain_summary.csv').open('w',encoding='utf-8-sig',newline='')as f:
        fields=['Domain','Rules','Finding_Groups','Independent_Rule_Match','R3_Class'];w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(summaries)
    report=dict(classifier_sha256=frozen,domains=len(records),matched_domains=sum(bool(x)for x in grouped.values()),finding_groups=len(all_findings),domain_findings=domain_findings,findings=all_findings,interpretation='Automated rule matches; not confirmed tracking. R3-only is structural and unconfirmed.')
    put(out/'argus_final_report.json',report)
    return {k:v for k,v in report.items()if k not in('domain_findings','findings')}

def analyze_one(job,out,engine,node,timeout=60,semantics=False,conditional=False):
    d=new_dir(out);source=Path(job['source']);engine=Path(engine).resolve();engine_hash=sha(engine)
    if sha(source)!=job['sha256']:raise ValueError('Input changed before analysis')
    put(d/'input_manifest.json',dict(job,engine_sha256=engine_hash,flags=FLAGS,limits=LIMITS))
    env=dict(os.environ,ARGUS_BABEL_ROOT=str(ROOT/'node_modules'));env.pop('NODE_OPTIONS',None);env.pop('NODE_PATH',None)
    pre=d/'preflight';pre.mkdir();scanfile=pre/'scan.json'
    ex=bounded.child([node,'--max-old-space-size=4096',SUPPORT/'r147_bounded_full_ast_v1/scanner.cjs',source,job['sha256'],scanfile],pre,pre/'logs',60,LIMITS,env,d,lambda _:None)
    put(pre/'execution.json',ex)
    scan=json.loads(scanfile.read_text())if scanfile.exists()else dict(status='HELD_PREFLIGHT',reason=ex['stop_reason']or ex['error']or'NO_SCAN')
    result=dict(domain=job['domain'],input_sha256=job['sha256'],engine_sha256=engine_hash,native_complete=False,native_attempted=False,preflight=scan,semantic_status='NOT_EVALUATED',site_benign_inference_allowed=False)
    if ex['returncode']!=0 or ex['stop_reason'] or ex['error']or scan.get('status')!='SCRIPT_STATIC_ADMITTED' or not scan.get('full_ast_scanned')or scan.get('signal_count')!=0:
        result['status']=scan['status'];put(d/'result.json',result);return result
    native=d/'native';native.mkdir();(native/'report').mkdir()
    inp=d/'input.js';shutil.copyfile(source,inp)
    if sha(inp)!=job['sha256']:raise ValueError('Input changed while staging')
    env=dict(os.environ,ARGUS_AUDIT_CAPTURE_PREFIX=str(native/'captured'),ARGUS_TAINT_COMPACT_SINK_DEBUG='1')
    env.pop('ARGUS_PRIVATE_ENTRY_PROFILE',None);env.pop('ARGUS_AUDIT_CAPTURE_ONLY',None)
    ex=bounded.child([sys.executable,'-B',SUPPORT/'transport.py',native/'native.stdout.gz',engine,*FLAGS,inp],native,native,timeout,LIMITS,env,d,lambda _:None)
    ex['pins_preserved']=sha(source)==sha(inp)==job['sha256'] and sha(engine)==engine_hash
    put(native/'execution.json',ex)
    verified=False
    try:
        receipt=json.loads((native/'native.stdout.receipt.json').read_text());transport.verify(native/'native.stdout.gz',receipt);verified=True
    except (OSError,ValueError,AssertionError,EOFError):pass
    a=stream_reader.analyze(dict(id=job['domain'],domain=job['domain'],source=str(inp),sha256=job['sha256'],arm='raw_base'),native,ex)
    complete=bool(verified and a['analysis_complete'] and not a['validation_errors'])
    put(native/'analysis.json',a)
    result.update(native_attempted=True,native_complete=complete,status='COMPLETE' if complete else a['status'],transport_verified=verified,analysis_file=str(native/'analysis.json'),diagnostics=a.get('diagnostics',[]),report=a['report_path'],report_sha256=a['report_sha256'],native_routes=a.get('total_emitted_routes'),date_cookie_routes=a.get('date_cookie_emitted_route_count'),seconds=ex['seconds'])
    result['semantic_guard']=semantic_guard.assess_verified(native/'native.stdout.gz',complete,result['date_cookie_routes'],gate.assess)
    result['semantic_status']=result['semantic_guard']['semantic_status']
    if complete and semantics:
        try:result['cookie_semantics']=run_semantics(job,d,native,a,engine_hash)
        except Exception as error:
                                                                          
            result['cookie_semantics']=dict(status='UNKNOWN',error=repr(error))
    if conditional:
        from argus_conditional.adapter import analyze_after_native
        result['conditional']=analyze_after_native(inp,job['sha256'],d/'conditional',a,native_artifacts=[native/'analysis.json'],unit_scope='COLLECTED_WHOLEPAGE_NATIVE_INPUT',node=node,babel_root=ROOT/'node_modules')
    put(d/'result.json',result)
    return result

def run_semantics(job,d,native,analysis,engine_hash):
    routes=[r for r in analysis['routes']if r['source_name']in('Date','Date.now') and r['sink_name']=='document.cookie']
    if not routes:return dict(status='NO_DATE_COOKIE_ROUTES',routes=0)
    stage=d/'semantic_input';base=stage/'ir'/job['domain'];base.mkdir(parents=True)
    receipt=json.loads((native/'native.stdout.receipt.json').read_text());ir=base/'functions.ir.gz';shutil.copyfile(native/'native.stdout.gz',ir)
    rp=base/'functions.ir.receipt.json';shutil.copyfile(native/'native.stdout.receipt.json',rp)
    storage=dict(encoding='gzip',file='functions.ir.gz',raw_bytes=receipt['raw_bytes'],compressed_bytes=receipt['compressed_bytes'],compressed_sha256=sha(ir),receipt_sha256=sha(rp))
    meta=dict(status='OK',engine_sha256=engine_hash,reconstructed_sha256=job['sha256'],ir_sha256=receipt['raw_sha256'],ir_storage=storage)
    put(base/'metadata.json',meta);put(base/'routes.json',routes)
                                                                                
                                                                                
    arguments=stage/'arguments'/job['domain'];arguments.mkdir(parents=True)
    os.link(ir,arguments/'full.ir.gz');os.link(rp,arguments/'full.ir.receipt.json')
    put(arguments/'metadata.json',dict(meta,base_ir_sha256=meta['ir_sha256'],complete_ir=True,
        ir_storage=dict(storage,file='full.ir.gz')))
    fields=['domain','route_id','source','sink','source_function','sink_function','source_location','sink_location']
    sample=stage/'routes.csv'
    with sample.open('w',encoding='utf-8-sig',newline='')as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in routes:w.writerow(dict(domain=job['domain'],route_id=r['route_id'],source=r['source_name'],sink=r['sink_name'],**{k:r[k] for k in ['source_function','sink_function']},**{k:json.dumps(r[k])for k in ['source_location','sink_location']}))
    output=d/'cookie_semantics';env=dict(os.environ,PYTHONPATH=str(ROOT),PYTHONDONTWRITEBYTECODE='1')
    ex=bounded.child([sys.executable,'-B','-m','argus_semantics.run','--sample',sample,'--ir-data',stage,'--argument-ir',stage/'arguments','--data',output,'--timeout','15','--quiet'],ROOT,d/'semantic_logs',60,LIMITS,env,d,lambda _:None)
    put(d/'semantic_execution.json',ex)
    return dict(status='COMPLETE'if ex['returncode']==0 and not ex['error']and not ex['stop_reason']else'UNKNOWN',routes=len(routes),output=str(output),execution=ex,scope='exact emitted Date source-to-cookie route; not site purpose')

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);subs=parser.add_subparsers(dest='command',required=True)
    a=subs.add_parser('analyze',help='Compile saved inputs, validate output, then run original rules')
    inputs=a.add_mutually_exclusive_group(required=True);inputs.add_argument('--input',type=Path);inputs.add_argument('--manifest',type=Path);inputs.add_argument('--crawl-dir',type=Path)
    a.add_argument('--domain');a.add_argument('--network-log',type=Path);a.add_argument('--out',type=Path,required=True);a.add_argument('--engine',type=Path,default=ROOT/'build/bin/mixed-hermes');a.add_argument('--node',default=shutil.which('node')or'node');a.add_argument('--workers',type=int,choices=range(1,5),default=1);a.add_argument('--timeout',type=int,default=60,choices=range(1,61));a.add_argument('--semantics',action='store_true');a.add_argument('--conditional',action='store_true')
    a.add_argument('--no-classify',action='store_true',help='Save completed-report manifest for a separate classification step')
    c=subs.add_parser('classify',help='Classify existing native reports without recompiling')
    c.add_argument('--manifest',type=Path,required=True,help='JSON list: domain, report, optional report_sha256 and network_log');c.add_argument('--out',type=Path,required=True)
    subs.add_parser('crawl',help='Pass remaining arguments to the preserved crawler')
    s=subs.add_parser('semantics',help='Pass arguments to the exact-route semantics classifier')
    if argv is None:argv=sys.argv[1:]
    if argv and argv[0]in('crawl','semantics'):
        env=dict(os.environ)
        env['PYTHONPATH']=str(ROOT)+(os.pathsep+env['PYTHONPATH'] if env.get('PYTHONPATH') else '')
        if argv[0]=='semantics':
            from argus_semantics.run import build_parser
            forwarded=build_parser().parse_args(argv[1:])
            if forwarded.data.exists():parser.error('--data must be a new output directory')
            cmd=[sys.executable,'-m','argus_semantics.run',*argv[1:]]
        else:cmd=[shutil.which('node')or'node',str(ROOT/'crawler/crawler.cjs'),*argv[1:]]
        return subprocess.call(cmd,cwd=Path.cwd(),env=env)
    args=parser.parse_args(argv)
    if sys.platform!='linux':parser.error('Use Linux or WSL2; resource bounds require prlimit and /proc.')
    if args.command=='classify':
        items=json.loads(args.manifest.read_text());base=args.manifest.resolve().parent
        records=[]
        for r in items:
            network=(base/r['network_log']).resolve() if r.get('network_log') else None
            if r.get('network_sha256') and (network is None or sha(network)!=r['network_sha256']):
                raise ValueError('Network evidence hash mismatch: '+r['domain'])
            records.append(dict(r,report=str((base/r['report']).resolve()),network_urls=read_network(network)))
        print(json.dumps(classify_records(records,args.out)));return 0
    if args.input:
        if not args.domain:parser.error('--domain is required with --input')
        jobs=normalize_jobs([dict(domain=args.domain,input=str(args.input),network_log=str(args.network_log)if args.network_log else None)],Path.cwd())
    elif args.manifest:jobs=normalize_jobs(json.loads(args.manifest.read_text()),args.manifest.resolve().parent)
    else:jobs=crawl_jobs(args.crawl_dir)
    if not args.engine.is_file():parser.error('Build native engine first: scripts/build.sh')
    available=next(int(x.split()[1])*1024 for x in Path('/proc/meminfo').read_text().splitlines()if x.startswith('MemAvailable:'))
    if available < (args.workers*8+2)*1024**3:parser.error('Insufficient available RAM for workers × 8 GiB plus 2 GiB reserve')
    if output_disk_free(args.out)<22*1024**3:parser.error('At least 22 GiB free disk required')
    out=new_dir(args.out);put(out/'manifest.json',jobs);results=[];start=time.time()
    def task(job):
        return analyze_one(job,out/'visits'/job['domain'],args.engine,args.node,args.timeout,args.semantics,args.conditional)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)as pool:
        futures={pool.submit(task,j):j for j in jobs}
        for future in concurrent.futures.as_completed(futures):
            j=futures[future]
            try:r=future.result()
            except Exception as e:r=dict(domain=j['domain'],native_complete=False,status='PIPELINE_ERROR',error=repr(e));put(out/'visits'/j['domain']/'pipeline_error.json',r)
            results.append(r);put(out/'results.json',results)
            progress=dict(processed=len(results),planned=len(jobs),native_complete=sum(x['native_complete']for x in results),seconds=time.time()-start,last_domain=j['domain'])
            put(out/'progress.json',progress);print(json.dumps(progress),flush=True)
    bydomain={j['domain']:j for j in jobs}
    records=[dict(domain=r['domain'],report=r['report'],report_sha256=r['report_sha256'],network_urls=bydomain[r['domain']]['network_urls'])for r in results if r['native_complete']]
    snapshots=out/'classification_network';snapshots.mkdir()
    classification_manifest=[]
    for r in records:
        net=snapshots/(r['domain']+'.json');put(net,r['network_urls'])
        classification_manifest.append(dict(domain=r['domain'],report=os.path.relpath(r['report'],out),report_sha256=r['report_sha256'],network_log=os.path.relpath(net,out),network_sha256=sha(net)))
    put(out/'classification_manifest.json',classification_manifest)
    rules=None if args.no_classify else classify_records(records,out/'rules')
    put(out/'final_summary.json',dict(processed=len(jobs),native_complete=len(records),not_complete=len(jobs)-len(records),rules=rules,classification_status='DEFERRED' if args.no_classify else 'COMPLETE',seconds=time.time()-start,semantic_unknown_is_not_negative=True))
    return 0 if len(records)==len(jobs)else 2

if __name__=='__main__':raise SystemExit(main())
