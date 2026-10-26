"""Evaluation only: audit CSV never feeds the classifier."""
import argparse,csv,json,hashlib
from collections import Counter
from pathlib import Path

SERIALIZATION={'TIMESTAMP_DERIVED_CONTENT_STATIC':'TIMESTAMP_EXPRESSION','FUNCTION_REFERENCE_STRING':'FUNCTION_REFERENCE','NOT_SERIALIZED_TYPEERROR':'TYPEERROR_BEFORE_SINK','INVALID_DATE':'INVALID_DATE'}
CONNECTION={'STATICALLY_SUPPORTED':'SUPPORTED','BLOCKED_BEFORE_SINK':'BLOCKED_BY_EXCEPTION','OBJECT_PROPERTY_REFERENCE_ONLY':'OBJECT_REFERENCE_ONLY','OBJECT_FLOW_WITH_INVALID_DATE':'OBJECT_FLOW_WITH_INVALID_DATE','NO_FEASIBLE_MATCHED_FLOW':'DISPROVED'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data',type=Path,required=True)
    p.add_argument('--audit',type=Path,required=True)
    a=p.parse_args()
    results=json.loads((a.data/'semantic_results.json').read_text())
    with a.audit.open(encoding='utf-8-sig') as f:gold={(r['domain'],int(r['route_id'])):r for r in csv.DictReader(f)}
    rows=[]
    for r in results:
        g=gold[(r['domain'],r['route_id'])]
        expected=g['final_label'] or None
        status='UNVERIFIED' if r['semantic_label']=='UNCLEAR' else 'MATCH' if r['semantic_label']==expected else 'MISMATCH'
        serial=SERIALIZATION.get(g['serialization_status'],g['serialization_status'])
        basis='UNVERIFIED' if r['purpose_basis']=='INSUFFICIENT_EVIDENCE' else 'MATCH' if r['purpose_basis']==g['purpose_basis'] else 'MISMATCH'
        delivery='UNVERIFIED' if r['serialization_status']=='UNKNOWN' else 'MATCH' if serial==r['serialization_status'] else 'MISMATCH'
        connection='UNVERIFIED' if r['connection_status']=='UNVERIFIED' else 'MATCH' if CONNECTION.get(g['connection_status'])==r['connection_status'] else 'MISMATCH'
        rows.append({'domain':r['domain'],'route_id':r['route_id'],'manual_label':expected,'automatic_label':r['semantic_label'],'label_comparison':status,'manual_purpose_basis':g['purpose_basis'],'automatic_purpose_basis':r['purpose_basis'],'basis_comparison':basis,'manual_serialization_status':g['serialization_status'],'automatic_serialization_status':r['serialization_status'],'serialization_comparison':delivery,'manual_connection_status':g['connection_status'],'automatic_connection_status':r['connection_status'],'connection_comparison':connection,'reason_code':r['reason_code'],'reason':r['reason'],'evidence':json.dumps({'file':r['evidence_path'],'record_count':len(r['evidence']),'rules':sorted({e['rule'] for e in r['evidence']})},ensure_ascii=False)})
    for filename,subset in [('comparison.csv',rows),('disagreements.csv',[r for r in rows if 'MISMATCH' in (r['label_comparison'],r['basis_comparison'],r['serialization_comparison'],r['connection_comparison'])]),('abstentions.csv',[r for r in rows if r['label_comparison']=='UNVERIFIED'])]:
        with (a.data/filename).open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(subset)
    counts=Counter(r['semantic_label'] or 'NOT_APPLICABLE' for r in results)
    summary={'total':len(rows),'labels':dict(counts),'decisive_coverage':sum(v for k,v in counts.items() if k!='UNCLEAR')/len(rows),'purpose_label_coverage':sum(counts[k] for k in ('BENIGN_EXPIRATION','BENIGN_FUNCTIONAL','TRACKING_RELATED'))/len(rows),'label_comparison':dict(Counter(r['label_comparison'] for r in rows)),'basis_comparison':dict(Counter(r['basis_comparison'] for r in rows)),'serialization_comparison':dict(Counter(r['serialization_comparison'] for r in rows)),'connection_comparison':dict(Counter(r['connection_comparison'] for r in rows)),'abstention_reasons':dict(Counter(r['reason_code'] for r in rows if r['label_comparison']=='UNVERIFIED')),'input_hashes':{'manual_audit_sha256':hashlib.sha256(a.audit.read_bytes()).hexdigest(),'automatic_results_sha256':hashlib.sha256((a.data/'semantic_results.json').read_bytes()).hexdigest()},'status_normalization':{'connection':CONNECTION,'serialization':SERIALIZATION},'limitations':['Development-set comparison; not independent generalization evaluation','No sampled TR positives; TR evaluated only by explicit synthetic API-contract tests','No population estimate']}
    (a.data/'comparison_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
    print(json.dumps(summary,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
