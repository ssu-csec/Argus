"""Reproduce original Argus CSV tables and descriptive destination counts.

Usage: python export_csv_and_tracker_counts.py --input final_classification.json.gz --output csv_export
No engine/classifier execution. Existing native/classifier outputs are read only.
New-to-a-blocklist / novel-tracker claims are deliberately NOT inferred.
"""
from pathlib import Path
from collections import Counter, defaultdict
from urllib.parse import urlsplit
import argparse, ast, csv, gzip, hashlib, json, re, shutil

HERE = Path(__file__).resolve().parent
p = argparse.ArgumentParser()
p.add_argument('--input', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--classifier', type=Path, default=HERE.parent/'classifier.py')
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
blob = a.input.read_bytes()
data = json.loads(gzip.decompress(blob))
rows = data['rows']; summary = data['summary']
assert len(rows) == len({r['domain'] for r in rows}) == summary['classified'] == 44882
fields = ['Domain','Threat_Type','Trigger_Context','Leaked_Data (Source)','Leak_Method (Sink)','Destination','Observed_Trackers','Party_Check','Confidence_Score']
summary_fields = ['Domain','Rule_1','Rule_2','Rule_3','Rule_4','Rule_5','Total_Routes','Max_Confidence','3rd_Party_Confirmed']
mixed_fields = ['Domain','AUTONOMOUS','EVENT_DRIVEN','UNKNOWN','Handlers','Rules','Mixed_Context','Independent_Rule_Match','Result_Class']
counts = {}; hashes = {}

def write_csv(name, headers, records):
    path = a.output/name
    n = 0
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=headers)
        writer.writeheader()
        for record in records:
            writer.writerow(record); n+=1
    with path.open(encoding='utf-8-sig',newline='') as f:
        reader=csv.DictReader(f)
        assert reader.fieldnames==headers
        assert sum(1 for _ in reader)==n
    counts[name]=n
    hashes[name]=hashlib.sha256(path.read_bytes()).hexdigest()

def rule_set(f):
    return {int(n) for n in re.findall(r'Rule ([1245])',f['Threat_Type'])}

findings=[f for r in rows for f in r['findings']]
findings.sort(key=lambda f:(min(rule_set(f)),f['Domain']))
assert len(findings)==summary['finding_groups']==191039
write_csv('malicious_domains_20261026.csv',fields,findings)

summaries=[]; mixed=[]; combos=Counter(); independent=Counter()
domains_by_rule=Counter(); groups_by_rule=Counter(); labels_by_rule=Counter()
for r in rows:
    dom=r['domain']; df=r['domain_finding']; rules=set()
    e=dict.fromkeys(summary_fields,0);e['Domain']=dom
    for f in r['findings']:
        rs=rule_set(f);rules.update(rs);groups_by_rule.update(rs)
        e['Total_Routes']+=1
        e['Max_Confidence']=max(e['Max_Confidence'],int(f['Confidence_Score']))
        e['3rd_Party_Confirmed']+=int('3rd-Party' in f['Party_Check'])
        for lab in f['Threat_Type'].split(' | '):
            for n in re.findall(r'Rule ([1245])',lab):
                e['Rule_'+n]+=1;labels_by_rule[int(n)]+=1
    independent[tuple(sorted(rules))]+=1
    is_mixed=bool(df['matched'] and df['valid_for_corrected_headline'])
    if is_mixed:
        e['Rule_3']=1;rules.add(3)
    assert rules==set(r['rule_numbers'])
    domains_by_rule.update(rules);combos[tuple(sorted(rules))]+=1
    summaries.append(e)
    if is_mixed:
        mixed.append(dict(Domain=dom,AUTONOMOUS=df['autonomous_route_count'],EVENT_DRIVEN=df['event_driven_route_count'],UNKNOWN=df['unknown_route_count'],Handlers=df['event_driven_functions_diagnostic'],Rules='+'.join('R'+str(n) for n in sorted(rules)),Mixed_Context='Mixed (Dual Context)',Independent_Rule_Match=int(bool(r['findings'])),Result_Class=df['result_class']))
summaries.sort(key=lambda x:(-x['Total_Routes'],x['Domain']))
write_csv('malicious_domains_20261026_summary.csv',summary_fields,summaries)
write_csv('mixed_dual_context_domains.csv',mixed_fields,mixed)
rule_rows=[]
for rr in summary['rules']:
    n=int(rr['rule'][1:]);assert domains_by_rule[n]==rr['domains']
    if n!=3:
        assert groups_by_rule[n]==rr['finding_groups'] and labels_by_rule[n]==rr['original_summary_label_count']
    rule_rows.append(dict(Rule='R'+str(n),Domains=domains_by_rule[n],Exclusive_Domains=combos[(n,)],Overlapping_Domains=domains_by_rule[n]-combos[(n,)],Finding_Groups='' if n==3 else groups_by_rule[n],Original_Summary_Label_Count=rr['original_summary_label_count']))
write_csv('rule_counts.csv',list(rule_rows[0]),rule_rows)
write_csv('rule_overlap_exact.csv',['Scope','Exact_Rules','Domains'],(dict(Scope=scope,Exact_Rules='+'.join('R'+str(n) for n in k) or 'NONE',Domains=v) for scope,ctr in [('R1_R2_R3_R4_R5',combos),('R1_R2_R4_R5',independent)] for k,v in sorted(ctr.items(),key=lambda kv:(len(kv[0]),kv[0]))))

                                                                       
tree=ast.parse(a.classifier.read_text(encoding='utf-8'))
keywords=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='TRACKER_KEYWORDS' for t in node.targets))
urlmap={};excluded=Counter();mixed_excluded=Counter()
markers=[' (🌟 Hybrid Reconstructed)',' (🌟 Predicted 1st-Party Target / CNAME Cloaked)']
for r in rows:
    mixed_domain=3 in r['rule_numbers']
    for f in r['findings']:
        dest=f['Destination'];kind='reported_literal';u=dest
        for marker in markers:
            if u.endswith(marker):
                u=u[:-len(marker)];kind='hybrid_or_predicted';break
        reason=None
        if not u or u=='DYNAMIC_URL' or '{VAR}' in u:reason='unresolved'
        elif not re.match(r'^https?://',u,re.I):reason='not_absolute_http_url'
        elif re.search(r'\s',u):reason='whitespace_or_unrecognized_annotation'
        try:
            parsed=urlsplit(u)
            if not reason and (not parsed.hostname or not parsed.netloc):reason='invalid_http_url'
        except ValueError:reason='invalid_http_url'
        if reason:
            excluded[reason]+=1
            if mixed_domain:mixed_excluded[reason]+=1
            continue
        if u not in urlmap:
            urlmap[u]=dict(domains=set(),mixed_domains=set(),kinds=set(),rules=set(),groups=0,host=parsed.hostname.lower(),disguised=False)
        item=urlmap[u];item['domains'].add(r['domain']);item['kinds'].add(kind);item['rules'].update(rule_set(f));item['groups']+=1
        item['disguised'] |= 'Disguised Tracker' in f['Threat_Type']
        if mixed_domain:item['mixed_domains'].add(r['domain'])
urlrows=[]
for u,item in sorted(urlmap.items()):
    hits=[kw for kw in keywords if kw in u.lower()]
    urlrows.append(dict(URL=u,Destination_Host=item['host'],Site_Domains=len(item['domains']),Mixed_Site_Domains=len(item['mixed_domains']),Finding_Groups=item['groups'],Rules='+'.join('R'+str(n) for n in sorted(item['rules'])),Evidence_Kinds=' | '.join(sorted(item['kinds'])),Classifier_Keyword_Matches=' | '.join(hits),Disguised_Tracker_Label=int(item['disguised']),Novelty_Status='NOT_EVALUATED',Example_Site_Domains=' | '.join(sorted(item['domains'])[:5])))
write_csv('unique_destination_urls.csv',list(urlrows[0]),urlrows)
mixedurls=[x for x in urlrows if x['Mixed_Site_Domains']]
write_csv('mixed_domain_destination_urls.csv',list(urlrows[0]),mixedurls)
urlstats=dict(unique_absolute_destination_urls=len(urlrows),unique_destination_hosts=len({x['Destination_Host'] for x in urlrows}),urls_in_mixed_domains=len(mixedurls),destination_hosts_in_mixed_domains=len({x['Destination_Host'] for x in mixedurls}),urls_without_classifier_keyword_match=sum(not x['Classifier_Keyword_Matches'] for x in urlrows),mixed_domain_urls_without_classifier_keyword_match=sum(not x['Classifier_Keyword_Matches'] for x in mixedurls),urls_with_disguised_tracker_label=sum(x['Disguised_Tracker_Label'] for x in urlrows),hybrid_or_predicted_only_urls=sum(x['Evidence_Kinds']=='hybrid_or_predicted' for x in urlrows),excluded_finding_groups=dict(excluded),excluded_mixed_finding_groups=dict(mixed_excluded),novel_tracker_url_count=None,novelty_reason='No versioned external tracker/blocklist baseline or historical URL set was compared. Keyword non-match does not establish novelty or tracking.')
assert len(mixed)==11152
assert sum(v for k,v in independent.items() if k)==33096
assert sum(e['Total_Routes'] for e in summaries)==191039
assert sum(x['groups'] for x in urlmap.values())+sum(excluded.values())==191039
result=dict(status='PASS',input_sha256=hashlib.sha256(blob).hexdigest(),domains=len(rows),finding_groups=len(findings),mixed_dual_context_domains=len(mixed),mixed_with_independent_match=sum(x['Independent_Rule_Match'] for x in mixed),mixed_only_unconfirmed=sum(not x['Independent_Rule_Match'] for x in mixed),url_statistics=urlstats,csv_rows=counts,csv_sha256=hashes,notes=['CSV detail rows preserve original classifier columns and values; footer sections are separated into tables.','Original summary Total_Routes means deduplicated finding groups, not native routes. Rule_1/2/4/5 count labels; Rule_3 is a domain boolean.','URL uniqueness is exact complete string after removing the two documented display annotations; query strings are retained. Hosts are lowercase hostnames, not registrable domains.','URLs are destinations retained by deduplicated classifier outputs, not an exhaustive raw-network inventory. Mixed context is a site-level property, not proof of mixed execution for every destination.'])
(a.output/'export_validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
shutil.copy2(a.classifier,a.output/'classifier.original.py')
shutil.copy2(HERE/'count_rule_overlap.py',a.output/'count_rule_overlap.py')
shutil.copy2(Path(__file__),a.output/Path(__file__).name)
(a.output/'HOW_TO_REPRODUCE.txt').write_text('Argus CSV export and descriptive counts\n\nRun with Python 3 (standard library only):\npython export_csv_and_tracker_counts.py --input PATH_TO_final_classification.json.gz --output NEW_OUTPUT_FOLDER\n\nOriginal input: '+str(a.input.resolve())+'\nSHA256: '+result['input_sha256']+'\n\n'+ '\n'.join(result['notes'])+'\n\nMixed (Dual Context): domain_finding.matched AND valid_for_corrected_headline.\nNew tracker discovery: NOT EVALUATED. No historical/blocklist novelty claim is made.\nKeyword non-match: literal substring non-match against the frozen classifier TRACKER_KEYWORDS; not a blacklist comparison.\nCSV format: UTF-8 BOM, same 9 detail columns as original Argus. Separate summary/overlap/URL tables avoid non-tabular footer rows.\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False,indent=2))
