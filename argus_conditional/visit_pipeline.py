#!/usr/bin/env python3
"""Versioned bridge with optional pbjs post-native sidecar.
No historical samples/labels are used. Each visit has an isolated analysis workdir.
Derived from pinned operational url_pipeline.py ad35b4ace61a94347edd6d124c4324a4d99b70944a5459208ade29051eb1f594.
The protected operational script and frozen jobs are not modified.
"""
import argparse, concurrent.futures as cf, csv, gzip, hashlib, json, os
from pathlib import Path
import re, shutil, signal, subprocess, sys, time
from collections import Counter
from datetime import datetime, timezone

VERSION = "url-pipeline-1"
def now(): return datetime.now(timezone.utc).isoformat()
def sha(p):
    h = hashlib.sha256()
    with Path(p).open("rb") as f:
        for block in iter(lambda: f.read(1024*1024), b""): h.update(block)
    return h.hexdigest()
def read(p): return json.loads(Path(p).read_text(encoding="utf-8"))
def put(p, obj):
    p = Path(p); tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(p)
def inside(root, relative):
    p = (root / relative).resolve()
    if not p.is_relative_to(root.resolve()): raise ValueError("Path outside crawl: " + str(relative))
    return p
def run(cmd, cwd, out, err, timeout, memory_gb=None, env=None):
    actual = list(map(str,cmd))
    if memory_gb:
        actual = ["prlimit", "--as="+str(int(memory_gb*1024**3)), "--core=0", "--"] + actual
    start = time.monotonic()
    with Path(out).open("wb") as stdout, Path(err).open("wb") as stderr:
        proc = subprocess.Popen(actual, cwd=cwd, stdout=stdout, stderr=stderr,
                                env=env, start_new_session=True)
        try: rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL); proc.wait()
            return dict(status="TIMEOUT", command=actual, seconds=round(time.monotonic()-start,3))
        except BaseException:
            os.killpg(proc.pid, signal.SIGTERM); proc.wait()
            raise
    return dict(status="OK" if rc==0 else "EXIT_"+str(rc), returncode=rc,
                command=actual, seconds=round(time.monotonic()-start,3))
def write_csv(path, fields, rows):
    with Path(path).open("w",encoding="utf-8-sig",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore");w.writeheader();w.writerows(rows)
def rows(path):
    with Path(path).open(encoding="utf-8-sig",newline="") as f: return list(csv.DictReader(f))
def compress(p):
    if p.is_file() and not p.is_symlink():
        with p.open("rb") as src, gzip.open(str(p)+".gz","wb",compresslevel=1) as dst:
            shutil.copyfileobj(src,dst,1024*1024)
        p.unlink()                                                                 
def safe_domain(d):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*",d or ""): raise ValueError("Unsupported hostname: "+str(d))
    return d.lower().rstrip(".")

SAMPLE_FIELDS = ["domain","route_id","source","sink","source_function","sink_function",
                 "source_location","sink_location"]
STATUS_FIELDS = ["visit_id","domain","input","crawl_status","status","native_status",
                 "general_status","semantic_status","native_routes","date_cookie_candidates",
                 "semantic_records","error","seconds","visit_result_directory"]

def analyze_visit(item, a, out, engine_hash):
    started=time.monotonic(); vid=item["visit_id"]; dest=out/"visits"/vid;dest.mkdir()
    s=dict(visit_id=vid,domain="",input=item.get("input",""),crawl_status=item["status"],
           status="UNAVAILABLE",native_status="NOT_RUN",general_status="NOT_RUN",
           semantic_status="NOT_RUN",native_routes=0,date_cookie_candidates=0,
           semantic_records=0,visit_result_directory=str(dest))
    put(dest/"input_outcome.json",item)
    ir=None; base=None
    try:
        if item["status"] not in ("SUCCESS","PARTIAL"):
            s["status"]="SKIPPED_CRAWL_"+item["status"];return s
        if shutil.disk_usage(out).free < a.min_free_gb*1024**3:
            s["status"]="SKIPPED_LOW_DISK";return s
        manifest=inside(a.crawl,item["visit_manifest"]);v=read(manifest)
        if v["visit_id"]!=vid or v["status"]!=item["status"]: raise ValueError("Visit identity/status mismatch")
        domain=safe_domain(v["hostname"]);s["domain"]=domain
        source=inside(manifest.parent,v["wholepage"]["file"])
        source_hash=sha(source)
        if source_hash!=v["wholepage"]["sha256"]:raise ValueError("Wholepage hash mismatch")
        put(dest/"provenance.json",dict(version=VERSION,crawl=str(a.crawl),visit_manifest=str(manifest),
            visit_manifest_sha256=sha(manifest),source=str(source),source_sha256=source_hash,
            engine_sha256=engine_hash,preprocessing="NONE",audit_labels_used=False,
            collection_status=v["status"],wholepage_semantics=v["wholepage"].get("semantics"),
            unit="crawl run + visit_id + native route_id; domain is an attribute"))
        (dest/"report").mkdir()
        ir=dest/"full.ir"
        command=[a.root/"build/bin/mixed-hermes","-O0","-custom-opt=taintanalysis",
                 "-custom-opt=auditor","-w","-dump-ir","-dump-source-location=loc",source]
        result=run(command,dest,ir,dest/"native.stderr.log",a.native_timeout,a.memory_gb)
        put(dest/"native_execution.json",result);s["native_status"]=result["status"]
        if getattr(a,"pbjs_conditional",False):
                                                                                 
            try:
                from .adapter import analyze_after_native
                conditional=analyze_after_native(source,source_hash,dest/"pbjs_conditional",result,
                    native_artifacts=[dest/"native_execution.json",dest/"provenance.json"],
                    unit_scope="COLLECTED_WHOLEPAGE_NATIVE_INPUT",
                    lineage=dict(visit_manifest=str(manifest),visit_manifest_sha256=sha(manifest),
                        composition_semantics=v["wholepage"].get("semantics"),
                        original_script_execution_context="UNRESOLVED"),
                    node=getattr(a,"pbjs_node","node"),babel_root=getattr(a,"pbjs_babel_root",None),
                    timeout_seconds=getattr(a,"pbjs_timeout",15.0))
                s["pbjs_conditional_status"]=conditional["status"]
                s["pbjs_conditional_summary"]=str(dest/"pbjs_conditional/summary.json")
            except Exception as exc:
                                                                                
                s["pbjs_conditional_status"]="INTEGRATION_UNAVAILABLE"
                s["pbjs_conditional_error"]=str(exc)
        if result["status"]!="OK":s["status"]="NATIVE_UNAVAILABLE";return s
        reports=list((dest/"report").glob("*report.json"))
        if len(reports)!=1:raise ValueError("Expected one fresh native report")
        report=reports[0];data=read(report);routes=data["s2s_routes"]
        if not isinstance(routes,list):raise ValueError("Invalid native route array")
        ids=[r["route_id"] for r in routes]
        if len(set(ids))!=len(ids):raise ValueError("Duplicate native route IDs")
        s["native_routes"]=len(routes)
                                                                                
                                                                                   
        home=dest/"classifier_home";legacy=home/"mixed-hermes"
        reportdir=legacy/"pipeline_results";reportdir.mkdir(parents=True)
        os.symlink(report,reportdir/(domain+"_report.json"))
        netdir=legacy/"crawler/collected_scripts"/domain;netdir.mkdir(parents=True)
        urls=sorted({r["url"] for r in v.get("requests",[]) if r.get("url","").startswith(("http://","https://"))
                     and (r.get("response_received_at") or r.get("finished_at"))
                     and r.get("collector_action")!="ABORT_RESOURCE_POLICY"})
        put(netdir/"network_logs.json",urls)
        put(dest/"network_projection.json",dict(policy="URLs with observed response or finish; excludes deliberately blocked resources",
            input=str(manifest),input_sha256=sha(manifest),output_sha256=sha(netdir/"network_logs.json"),count=len(urls),
            note="Format adapter only; original detailed request records remain in crawl. Not proof of tracking execution."))
        env=dict(os.environ,HOME=str(home),PYTHONPATH=str(a.root),PYTHONIOENCODING="utf-8")
        gr=run([sys.executable,a.root/"classifier.py","--summary"],dest,
               dest/"general.stdout.log",dest/"general.stderr.log",a.native_timeout,a.memory_gb,env)
        put(dest/"general_execution.json",gr);s["general_status"]=gr["status"]
        candidates=[r for r in routes if r.get("source_name") in ("Date","Date.now")
                    and r.get("sink_name")=="document.cookie"]
        s["date_cookie_candidates"]=len(candidates)
        if not candidates:
            s["semantic_status"]="NO_DATE_COOKIE_CANDIDATES"
        else:
            base=dest/"semantic_input/ir"/domain;base.mkdir(parents=True)
                                                                                
                                                                                   
            os.link(ir,base/"functions.ir")
            put(base/"routes.json",candidates)
            ih=sha(ir)
            meta=dict(status="OK",domain=domain,engine_sha256=engine_hash,
                      reconstructed_sha256=source_hash,ir_sha256=ih,
                      mode="fresh_compile_only_native_and_auditor",command=list(map(str,command)))
            put(base/"metadata.json",meta)
            arg=dest/"arguments"/domain;arg.mkdir(parents=True)
            os.link(ir,arg/"full.ir")
            put(arg/"metadata.json",dict(meta,base_ir_sha256=ih,complete_ir=True))
            sample=[]
            for r in candidates:
                sample.append(dict(domain=domain,route_id=r["route_id"],
                    source=r["source_name"],sink=r["sink_name"],
                    source_function=r["source_function"],sink_function=r["sink_function"],
                    source_location=json.dumps(r["source_location"],ensure_ascii=False),
                    sink_location=json.dumps(r["sink_location"],ensure_ascii=False)))
            write_csv(dest/"date_cookie_candidates.csv",SAMPLE_FIELDS,sample)
            sr=run([sys.executable,"-m","argus_semantics.run","--sample",dest/"date_cookie_candidates.csv",
                    "--ir-data",dest/"semantic_input","--argument-ir",dest/"arguments",
                    "--data",dest/"semantics","--timeout",a.route_timeout,"--quiet"],a.root,
                   dest/"semantic.stdout.log",dest/"semantic.stderr.log",
                   a.semantic_timeout,a.memory_gb,dict(os.environ,PYTHONPATH=str(a.root)))
            put(dest/"semantic_execution.json",sr);s["semantic_status"]=sr["status"]
            if sr["status"]=="OK":
                results=read(dest/"semantics/semantic_results.json")
                expected={(domain,r["route_id"]) for r in candidates}
                keys=[(r["domain"],r["route_id"]) for r in results]
                if len(set(keys))!=len(keys) or set(keys)!=expected:raise ValueError("Semantic output key mismatch")
                s["semantic_records"]=len(results)
                if any(r.get("reason_code")=="IR_OR_ANALYSIS_UNAVAILABLE" for r in results):
                    s["semantic_status"]="COMPLETED_WITH_UNAVAILABLE_ROUTES"
        s["status"]="COMPLETED" if s["general_status"]=="OK" and s["semantic_status"] in ("OK","NO_DATE_COOKIE_CANDIDATES") else "PARTIAL_ANALYSIS"
    except Exception as exc:
        s["error"]=type(exc).__name__+": "+str(exc);s["status"]="UNAVAILABLE"
    finally:
                                                                          
        if ir and ir.exists() and not a.keep_ir:
            try:
                links=[p for p in (dest/"semantic_input").glob("ir/*/functions.ir")]
                links+=list((dest/"arguments").glob("*/full.ir"))
                compress(ir)
                for p in links:p.unlink()
                put(dest/"ir_archive.json",dict(file="full.ir.gz",sha256=sha(dest/"full.ir.gz"),
                    restore_to=["full.ir"]+[str(p.relative_to(dest)) for p in links],
                    note="gunzip -c full.ir.gz restores original IR bytes; recreate listed hardlinks before standalone semantic rerun"))
            except Exception as exc:s["ir_archive_error"]=str(exc)
        s["seconds"]=round(time.monotonic()-started,3);put(dest/"status.json",s)
    return s

def analyze(a):
    a.crawl=a.crawl.resolve();out=a.out.resolve()
    crawl=read(a.crawl/"run.json");items=read(a.crawl/"outcomes.json")
    ids=[r["visit_id"] for r in items]
    if len(ids)!=len(set(ids)) or any(not re.fullmatch(r"\d+",str(i)) for i in ids):
        raise ValueError("Invalid/duplicate visit IDs")
    out.mkdir(parents=True);(out/"visits").mkdir()
    engine_hash=sha(a.root/"build/bin/mixed-hermes")
    settings={k:str(v) if isinstance(v,Path) else v for k,v in vars(a).items()}
    record=dict(version=VERSION,state="RUNNING",started_at=now(),crawl_run=str(a.crawl),
                crawl_manifest_sha256=sha(a.crawl/"run.json"),outcomes_sha256=sha(a.crawl/"outcomes.json"),
                engine_sha256=engine_hash,classifier_sha256=sha(a.root/"classifier.py"),
                semantics_code_sha256={p.name:sha(p) for p in (a.root/"argus_semantics").glob("*.py")},
                runner_sha256=sha(__file__),settings=settings,total_visits=len(items))
    put(out/"run.json",record)
    counts=Counter();labels=Counter();candidate_total=0;semantic_total=0
    import contextlib
    with contextlib.ExitStack() as stack:
        statusf=stack.enter_context((out/"visit_status.csv").open("w",encoding="utf-8-sig",newline=""))
        sw=csv.DictWriter(statusf,fieldnames=STATUS_FIELDS,extrasaction="ignore");sw.writeheader()
        jf=stack.enter_context((out/"visit_status.jsonl").open("w",encoding="utf-8"))
        semf=stack.enter_context((out/"semantic_results.csv").open("w",encoding="utf-8-sig",newline=""))
        sf=None
        generalf=stack.enter_context((out/"domain_findings.csv").open("w",encoding="utf-8-sig",newline=""))
        gf=None
        rulef=stack.enter_context((out/"rule_findings.csv").open("w",encoding="utf-8-sig",newline=""))
        rw=None
        with cf.ThreadPoolExecutor(max_workers=a.workers) as pool:
            iterator=iter(items)
            pending={}
            def submit():
                item=next(iterator,None)
                if item is not None:pending[pool.submit(analyze_visit,item,a,out,engine_hash)]=item
            for _ in range(a.workers):submit()
            while pending:
                done,_=cf.wait(pending,return_when=cf.FIRST_COMPLETED)
                for fut in done:
                    pending.pop(fut);s=fut.result()
                    counts[s["status"]]+=1;candidate_total+=s["date_cookie_candidates"];semantic_total+=s["semantic_records"]
                    sw.writerow(s);statusf.flush();jf.write(json.dumps(s,ensure_ascii=False)+"\n");jf.flush()
                    dest=Path(s["visit_result_directory"])
                    if s["semantic_records"]:
                        for r in rows(dest/"semantics/semantic_results.csv"):
                            r=dict(crawl_run_id=crawl.get("run_id",a.crawl.name),visit_id=s["visit_id"],
                                   crawl_status=s["crawl_status"],visit_result_directory=str(dest),**r)
                            if sf is None:sf=csv.DictWriter(semf,fieldnames=list(r));sf.writeheader()
                            sf.writerow(r);labels[r["semantic_label"] or "NO_SEMANTIC_LABEL"]+=1
                        semf.flush()
                    if s["general_status"]=="OK":
                        for p in (dest/"classifier_home/mixed-hermes/csv_reports").glob("domain_findings_*.csv"):
                            for r in rows(p):
                                r=dict(visit_id=s["visit_id"],crawl_status=s["crawl_status"],
                                       visit_result_directory=str(dest),**r)
                                if gf is None:gf=csv.DictWriter(generalf,fieldnames=list(r));gf.writeheader()
                                gf.writerow(r)
                        generalf.flush()
                        for p in (dest/"classifier_home/mixed-hermes/csv_reports").glob("malicious_domains_*.csv"):
                            if p.stem.endswith("_summary"):continue
                            for r in rows(p):
                                if not r.get("Domain") or not r.get("Threat_Type"):break
                                if not r.get("Leak_Method (Sink)"):continue
                                r=dict(visit_id=s["visit_id"],crawl_status=s["crawl_status"],
                                       visit_result_directory=str(dest),**r)
                                if rw is None:rw=csv.DictWriter(rulef,fieldnames=list(r));rw.writeheader()
                                rw.writerow(r)
                        rulef.flush()
                    progress=dict(processed=sum(counts.values()),total=len(items),statuses=dict(counts),
                        date_cookie_candidates=candidate_total,semantic_records=semantic_total,
                        semantic_labels=dict(labels),unavailable_candidate_results=candidate_total-semantic_total)
                    put(out/"progress.json",progress)
                    print("[ANALYSIS]",s["visit_id"],s["domain"],s["status"],f'{progress["processed"]}/{len(items)}',flush=True)
                    submit()
        if sf is None:semf.write("crawl_run_id,visit_id,crawl_status,visit_result_directory,domain,route_id,semantic_label\n")
        if gf is None:generalf.write("visit_id,crawl_status,visit_result_directory,Domain\n")
        if rw is None:rulef.write("visit_id,crawl_status,visit_result_directory,Domain,Threat_Type\n")
    record.update(state="COMPLETED",finished_at=now(),summary=progress if items else dict(processed=0,total=0))
    put(out/"run.json",record)
    print("Analysis output:",out,flush=True)
    return 2 if counts and any(k!="COMPLETED" for k in counts) else 0

def crawl(a):
    a.urls=a.urls.resolve()
    if not a.urls.is_file():raise ValueError("URL list not found: "+str(a.urls))
    a.out.mkdir(parents=True)                                 
    shutil.copyfile(a.urls,a.out/"input_urls.txt")
    cmd=["node",str(a.root/"crawler/crawler.cjs"),str(a.out/"input_urls.txt"),
         "--out",str(a.out/"crawl"),"--dependency-root",str(a.root/"crawler"),
         "--concurrency",str(a.concurrency),"--transform",a.transform]
    meta=dict(version=VERSION,state="CRAWLING",started_at=now(),url_list_sha256=sha(a.urls),
              runner_sha256=sha(__file__),command=cmd)
    put(a.out/"pipeline.json",meta)
                                                                                   
    rc=subprocess.call(cmd,cwd=a.root)
    meta.update(crawler_exit=rc,state="CRAWL_FINISHED",crawl_finished_at=now())
    put(a.out/"pipeline.json",meta)
    return rc

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=["all","crawl","analyze"])
    p.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument("--urls",type=Path);p.add_argument("--crawl",type=Path)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--concurrency",type=int,default=4)
    p.add_argument("--workers",type=int,default=2)
    p.add_argument("--memory-gb",type=float,default=20)
    p.add_argument("--native-timeout",type=int,default=300)
    p.add_argument("--semantic-timeout",type=int,default=900)
    p.add_argument("--route-timeout",type=int,default=15)
    p.add_argument("--min-free-gb",type=float,default=15)
    p.add_argument("--transform",choices=["preserve","babel"],default="preserve")
    p.add_argument("--keep-ir",action="store_true")
    p.add_argument("--pbjs-conditional",action="store_true",help="Write separate conditional observations after native analysis")
    p.add_argument("--pbjs-node",default="node")
    p.add_argument("--pbjs-babel-root")
    p.add_argument("--pbjs-timeout",type=float,default=15.0)
    a=p.parse_args();a.root=a.root.resolve();a.out=a.out.resolve()
    for name in ("workers","concurrency","memory_gb","native_timeout","semantic_timeout","route_timeout"):
        if getattr(a,name)<=0:p.error(name+" must be positive")
    if not 0<a.pbjs_timeout<=60:p.error("pbjs-timeout must be in (0, 60]")
    if a.mode in ("all","crawl") and not a.urls:p.error("--urls is required")
    if a.mode=="analyze" and not a.crawl:p.error("--crawl is required")
    if a.mode=="analyze":return analyze(a)
    rc=crawl(a)
    if a.mode=="crawl":return rc
    original=a.out
    if not (original/"crawl/outcomes.json").is_file():
        print("Crawl did not produce outcomes; analysis not started",file=sys.stderr);return 1
    a.crawl=original/"crawl";a.out=original/"analysis"
    arc=analyze(a)
    meta=read(original/"pipeline.json");meta.update(state="COMPLETED",finished_at=now(),analysis_exit=arc)
    put(original/"pipeline.json",meta)
    return 1 if rc not in (0,2) else max(rc,arc)

if __name__=="__main__":
    try: sys.exit(main())
    except KeyboardInterrupt: print("Interrupted; preserved existing outputs.",file=sys.stderr);sys.exit(130)
    except Exception as exc: print(type(exc).__name__+": "+str(exc),file=sys.stderr);sys.exit(1)
