"""Add semantic output to historical candidates, without reading audit labels."""
import argparse,csv,hashlib,json,signal,time
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
from . import VERSION
from .engine import classify
from .ir import parse
from .ir_storage import read_ir

def build_parser():
    p=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    p.add_argument('--sample',type=Path,required=True)
    p.add_argument('--data',type=Path,required=True,help='collect output directory')
    p.add_argument('--ir-data',type=Path,help='read-only existing collection; defaults to --data')
    p.add_argument('--helpers',type=Path,help='optional hash-verified additional helper IR')
    p.add_argument('--contexts',type=Path,help='optional complete creation index and bounded context IR')
    p.add_argument('--argument-ir',type=Path,help='optional complete hash-verified lexical use inventory for v4')
    p.add_argument('--timeout',type=int,default=15,choices=range(1,61),help='per-route analysis seconds (POSIX)')
    p.add_argument('--quiet',action='store_true')
    p.add_argument('--no-local-roles',action='store_true',help='timing/control run of unchanged legacy decisions only')
    return p

def main(argv=None):
    a=build_parser().parse_args(argv)
    with a.sample.open(encoding='utf-8-sig') as f:sample=list(csv.DictReader(f))
    remaining=Counter(r['domain'] for r in sample)
    ir_data=a.ir_data or a.data
    a.data.mkdir(parents=True,exist_ok=True)
    cache={};outputs=[];started=time.monotonic();helper_hashes={};ir_hashes={};context_hashes={};argument_hashes={}
    phase_seconds=dict(input_load_parse_index=0.0,legacy_classification=0.0,local_role=0.0,conditional_observation=0.0)
    for row in sample:
        route_started=time.monotonic()
        domain=row['domain'];rid=int(row['route_id'])
        result={'domain':domain,'route_id':rid,'classifier_version':VERSION,
                'semantic_label':'UNCLEAR','purpose_basis':'INSUFFICIENT_EVIDENCE',
                'cookie_field':'UNKNOWN','connection_status':'UNVERIFIED','serialization_status':'UNKNOWN',
                'reason':'IR_UNAVAILABLE','evidence':[],'roles':[]}
        try:
            if domain not in cache:
                phase_start=time.monotonic()
                base=ir_data/'ir'/domain
                meta=json.loads((base/'metadata.json').read_text())
                if meta['status']!='OK':raise ValueError(meta.get('error','IR unavailable'))
                raw=read_ir(base,'functions.ir',meta)
                if hashlib.sha256(raw).hexdigest()!=meta['ir_sha256']:raise ValueError('IR hash mismatch')
                ir_hashes[domain]=meta['ir_sha256']
                extra=b''
                if a.helpers and (a.helpers/domain/'metadata.json').exists():
                    hb=a.helpers/domain;hm=json.loads((hb/'metadata.json').read_text())
                    extra=read_ir(hb,'functions.ir',hm)
                    if (hm['status']!='OK' or hm['engine_sha256']!=meta['engine_sha256'] or
                        hm['reconstructed_sha256']!=meta['reconstructed_sha256'] or
                        hm['base_ir_sha256']!=meta['ir_sha256'] or hashlib.sha256(extra).hexdigest()!=hm['ir_sha256']):
                        raise ValueError('helper provenance/hash mismatch')
                    helper_hashes[domain]=hm['ir_sha256']
                context=b'';ci=None
                if a.contexts and (a.contexts/domain/'metadata.json').exists():
                    cb=a.contexts/domain;cm=json.loads((cb/'metadata.json').read_text())
                    context=read_ir(cb,'functions.ir',cm);index=(cb/'index.json').read_bytes()
                    if (cm['status']!='OK' or cm['engine_sha256']!=meta['engine_sha256'] or cm['reconstructed_sha256']!=meta['reconstructed_sha256'] or cm['base_ir_sha256']!=meta['ir_sha256'] or hashlib.sha256(context).hexdigest()!=cm['ir_sha256'] or hashlib.sha256(index).hexdigest()!=cm['index_sha256']):raise ValueError('context provenance/hash mismatch')
                    ci=json.loads(index);context_hashes[domain]={'ir_sha256':cm['ir_sha256'],'index_sha256':cm['index_sha256']}
                fs=parse((raw+b'\n'+extra+b'\n'+context).decode())
                if ci and ci['complete_creation_scan']:fs.creation_index=ci['all_creation_sites']
                if a.argument_ir and (a.argument_ir/domain/'metadata.json').exists():
                    from .arguments import Inventory
                    ab=a.argument_ir/domain;am=json.loads((ab/'metadata.json').read_text());full=read_ir(ab,'full.ir',am)
                    if am['status']!='OK' or am['engine_sha256']!=meta['engine_sha256'] or am['reconstructed_sha256']!=meta['reconstructed_sha256'] or am['base_ir_sha256']!=meta['ir_sha256'] or hashlib.sha256(full).hexdigest()!=am['ir_sha256']:raise ValueError('argument IR provenance/hash mismatch')
                    if am.get('complete_ir') is True:
                        from .number_bindings import verified_inventory
                        fs.argument_inventory=verified_inventory(full,am,meta)
                    else:
                        fs.argument_inventory=Inventory(parse(full.decode(),complete=True))
                    argument_hashes[domain]=am['ir_sha256']
                cache[domain]=(fs,json.loads((base/'routes.json').read_text()))
                phase_seconds['input_load_parse_index']+=time.monotonic()-phase_start
            fs,routes=cache[domain]
            r=next(r for r in routes if r['route_id']==rid)
            if row['source']!=r['source_name'] or row['sink']!=r['sink_name']:raise ValueError('API mismatch')
            for side in ('source','sink'):
                loc=json.loads(row[side+'_location'])
                if any(loc[k]!=r[side+'_location'][k] for k in ('line','column')) or row[side+'_function']!=r[side+'_function']:
                    raise ValueError('sample/report endpoint mismatch')
            def expired(*_):raise TimeoutError('route analysis time budget')
            signal.signal(signal.SIGALRM,expired);signal.alarm(a.timeout)
            phase_start=time.monotonic()
            try:result.update(classify(fs,r))
            finally:
                signal.alarm(0);phase_seconds['legacy_classification']+=time.monotonic()-phase_start
            if not a.no_local_roles:
                from .local_roles import analyze,unavailable
                phase_start=time.monotonic();signal.alarm(a.timeout)
                try:result['local_role'],result['sink_identity']=analyze(fs,r,result)
                except Exception as exc:
                                                                              
                    result['local_role']=unavailable('LOCAL_ROLE_UNAVAILABLE',f'{type(exc).__name__}: {exc}')
                    result['sink_identity']=dict(status='UNVERIFIED',reason='AUXILIARY_UNAVAILABLE',evidence=[])
                finally:
                    signal.alarm(0);result['local_role_seconds']=time.monotonic()-phase_start
                    phase_seconds['local_role']+=result['local_role_seconds']
                from .observations import analyze as observe, unavailable as no_observation, execution_summary
                phase_start=time.monotonic();signal.alarm(a.timeout)
                try:
                    result['execution_uncertainty']=execution_summary(result,result['local_role'])
                    result['conditional_read_insertion']=observe(fs,r,result,result['local_role'],result['sink_identity'])
                except Exception as exc:
                    result['conditional_read_insertion']=no_observation(f'{type(exc).__name__}: {exc}','ANALYSIS_LIMIT')
                finally:
                    signal.alarm(0);phase_seconds['conditional_observation']+=time.monotonic()-phase_start
            result['source_location']=r['source_location'];result['sink_location']=r['sink_location']
            result['source_function']=r['source_function'];result['sink_function']=r['sink_function']
        except Exception as exc:
            result['reason_code']='IR_OR_ANALYSIS_UNAVAILABLE'
            result['reason']=f'자료 또는 분석을 사용할 수 없습니다: {type(exc).__name__}: {exc}'
        from .observations import unavailable as no_observation
        result.setdefault('conditional_read_insertion',no_observation('DISABLED_OR_LEGACY_ANALYSIS_UNAVAILABLE'))
        result.setdefault('execution_uncertainty',dict(status='NOT_ANALYZED',findings=[],execution_success='NOT_PROVEN',browser_storage='NOT_TESTED'))
        evidence_path=Path('evidence')/domain/f'{rid}.json'
        target=a.data/evidence_path;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(json.dumps({'domain':domain,'route_id':rid,'evidence':result['evidence'],'date_states':result.get('date_states',[]),'rejected_memory_bridges':result.get('rejected_memory_bridges',[]),'local_role':result.get('local_role'),'sink_identity':result.get('sink_identity'),'conditional_read_insertion':result['conditional_read_insertion'],'execution_uncertainty':result['execution_uncertainty']},ensure_ascii=False,indent=2))
        result['evidence_path']=str(evidence_path)
        result['analysis_seconds']=round(time.monotonic()-route_started,6)
        outputs.append(result)
        remaining[domain]-=1
        if remaining[domain]==0 and domain in cache and hasattr(cache[domain][0],'argument_inventory'):
            del cache[domain][0].argument_inventory
        if not a.quiet:print(domain,rid,result['semantic_label'],result['reason'],flush=True)
    (a.data/'semantic_results.json').write_text(json.dumps(outputs,ensure_ascii=False,indent=2))
    fields=['domain','route_id','semantic_label','purpose_basis','cookie_field','cookie_field_basis','roles','connection_status','serialization_status','reason_code','reason','classifier_version','reported_path_status','rejected_memory_bridges','evidence_path','evidence','analysis_seconds','local_role','sink_identity','local_role_seconds','date_states','conditional_read_insertion','execution_uncertainty']
    with (a.data/'semantic_results.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in outputs:
            row={k:json.dumps(r.get(k),ensure_ascii=False) if isinstance(r.get(k),(list,dict)) else r.get(k) for k in fields}
            row['evidence']=json.dumps({'file':r['evidence_path'],'record_count':len(r['evidence']),'rules':sorted({e['rule'] for e in r['evidence']})},ensure_ascii=False)
            for name in ('local_role','sink_identity'):
                if name in r:row[name]=json.dumps({**{k:v for k,v in r[name].items() if k!='evidence'},'evidence_file':r['evidence_path']},ensure_ascii=False)
            w.writerow(row)
    (a.data/'argument_metadata.json').write_text(json.dumps(dict(ir_sha256=argument_hashes,settings=dict(depth=16,callsites_per_binding=8,nodes=256,CFG_states=1000),audit_labels_used_as_input=False),indent=2))
    package=Path(__file__).parent
    (a.data/'phase_timing.json').write_text(json.dumps(dict(seconds=phase_seconds,new_ir_compilation_seconds=0,local_roles_enabled=not a.no_local_roles,scope='same-run phase timings; load includes hash/read/parse/argument indexing; no comparison of historical wall times'),indent=2))
    (a.data/'classification_metadata.json').write_text(json.dumps({'classifier_version':VERSION,'generated_at_utc':datetime.now(timezone.utc).isoformat(),'sample_sha256':hashlib.sha256(a.sample.read_bytes()).hexdigest(),'code_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in package.glob('*.py')},'schema_sha256':hashlib.sha256((package/'schema.json').read_bytes()).hexdigest(),'engine_hashes':sorted({json.loads(p.read_text())['engine_sha256'] for p in (ir_data/'ir').glob('*/metadata.json')}),'ir_input_directory':str(ir_data.resolve()),'ir_sha256':ir_hashes,'helper_ir_sha256':helper_hashes,'context_sha256':context_hashes,'elapsed_seconds':time.monotonic()-started,'max_route_seconds':max((r['analysis_seconds'] for r in outputs),default=0.0),'timeout_count':sum('TimeoutError' in r['reason'] for r in outputs),'analysis_limit_count':sum(r.get('reason_code','').startswith('ANALYSIS_LIMIT') for r in outputs),'settings':{'slice_steps':12000,'recursive_values':90,'CFG_states':1000,'max_expression_alternatives':32,'helper_instructions':256,'helper_depth':1,'context_owner_instructions':3000,'context_callsites':8,'context_wrapper_depth':0,'route_timeout_seconds':a.timeout,'tracking_contracts':['analytics.identify argument 0','analytics.alias argument 0'],'audit_labels_used_as_input':False}},indent=2))

if __name__=='__main__':main()
