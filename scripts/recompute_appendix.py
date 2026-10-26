"""Recompute appendix aggregates from archived classifier and comparison inputs.
Requires Python 3; writes only --output. Run --help for input options.
"""
from pathlib import Path
import argparse, collections, csv, gzip, hashlib, json, re, statistics
from urllib.parse import urlsplit
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--classification', required=True, type=Path)
p.add_argument('--comparison', required=True, type=Path)
p.add_argument('--comparison-summary', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a=p.parse_args()
CLASS,COMPARE,SUMMARY=a.classification,a.comparison,a.comparison_summary
hashfile=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
with gzip.open(CLASS,'rt',encoding='utf-8') as f: data=json.load(f)
rows=[r for r in data['rows'] if r['domain_finding']['matched'] and r['domain_finding']['valid_for_corrected_headline'] and r['findings']]
assert len(rows)==11124
with COMPARE.open(encoding='utf-8-sig',newline='') as f: comp={x['Domain']:x for x in csv.DictReader(f)}
assert len(comp)==11124 and set(comp)=={r['domain'] for r in rows}
for r in rows:
    assert r['wholepage_sha256']==comp[r['domain']]['Wholepage_SHA256']
    assert r['network_urls_sha256']==comp[r['domain']]['Network_URLs_SHA256']
    assert len(r['findings'])==int(comp[r['domain']]['Finding_Groups'])
fs=[f for r in rows for f in r['findings']]
assert len(fs)==93902
statuses=['LIST_MATCHED','NO_LIST_MATCH_OBSERVED','INDETERMINATE_INCOMPLETE_NETWORK']
cohorts={s:[r for r in rows if comp[r['domain']]['Status']==s] for s in statuses}
groups={s:[f for r in cohorts[s] for f in r['findings']] for s in statuses}
rules=lambda f:set(map(int,re.findall(r'Rule\s+(\d+)',f['Threat_Type'])))
assert all(rules(f) and rules(f)<=set([1,2,4,5]) for f in fs)
unresolved = lambda f: (
    f['Destination'] == 'DYNAMIC_URL'
    or '{VAR}' in f['Destination']
)
hidden=lambda f:f['Leaked_Data (Source)'].startswith(('Obfuscated_Property','Obfuscated_Call'))
r4=lambda f:4 in rules(f)
props={'Unresolved source':hidden,'Unresolved URL':unresolved,'R4 match':r4,'All three':lambda f:hidden(f) and unresolved(f) and r4(f)}
metric={'inputs':{str(p):hashfile(p) for p in [CLASS,COMPARE,SUMMARY]},'cohort_domains':len(rows),'cohort_groups':len(fs),'counting_unit':'Final classifier deduplicated finding group; R3 excluded from group-level rule counts','list_cohorts':{s:{'domains':len(cohorts[s]),'groups':len(groups[s])} for s in statuses}}
bins=[]
for lo,hi in [(1,1),(2,3),(4,5),(6,10),(11,20),(21,45)]:
    rr=[r for r in rows if lo<=len(r['findings'])<=hi]
    bins.append({'range':str(lo) if lo==hi else f'{lo}--{hi}','domains':len(rr),'groups':sum(len(r['findings']) for r in rr)})
assert sum(x['domains'] for x in bins)==11124 and sum(x['groups'] for x in bins)==93902
metric['bins']=bins
metric['mean_groups']=len(fs)/len(rows);metric['median_groups']=statistics.median(len(r['findings']) for r in rows)
metric['properties']={name:{s:sum(any(pred(f) for f in r['findings']) for r in cohorts[s]) for s in statuses} for name,pred in props.items()}
metric['contexts']={s:dict(collections.Counter(f['Trigger_Context'] for f in groups[s])) for s in statuses}
metric['rule_complexity']={s:dict(collections.Counter(len(rules(f)) for f in groups[s])) for s in statuses}
metric['max_scores']={s:dict(collections.Counter(max(int(f['Confidence_Score']) for f in r['findings']) for r in cohorts[s])) for s in statuses}
metric['rule_subcategories']={name:sum(pred(f) for f in fs) for name,pred in {'R4_dynamic':lambda f:4 in rules(f) and '[Dynamic Obfuscated]' in f['Threat_Type'],'R5_D':lambda f:5 in rules(f) and '[Deterministic]' in f['Threat_Type'],'R5_P':lambda f:5 in rules(f) and '[Probabilistic]' in f['Threat_Type'],'R5_device':lambda f:'Fingerprinting_Leak' in f['Threat_Type']}.items()}
cname=[f for f in fs if 'CNAME Cloaked' in f['Destination']]
cnamesites={f['Domain'] for f in cname}
metric['cname_groups']=len(cname);metric['cname_domains']=len(cnamesites)
hosts=collections.Counter()
for domain in sorted(cnamesites):
    observed=set()
    for f in cname:
        if f['Domain']==domain:
            observed.update(x.strip() for x in f['Observed_Trackers'].split('|') if x.strip() and x.strip()!='N/A')
    hosts.update(observed)
metric['cname_coobserved_hosts']=sorted(hosts.items(),key=lambda x:(-x[1],x[0]))[:7]
front_counts=collections.Counter((f['Domain'],urlsplit(f['Destination'].split(' (')[0]).hostname) for f in cname)
ex=[{'domain':domain,'fronts':[front],'groups':n} for (domain,front),n in sorted(front_counts.items(),key=lambda x:(-x[1],x[0]))[:5]]
metric['cname_examples']=ex
a.output.write_text(json.dumps(metric,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
