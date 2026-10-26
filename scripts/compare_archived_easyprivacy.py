"""Offline domain-list coverage for preserved mixed-context candidates.

No crawl, native run, rule reclassification or source mutation.
This is host-list coverage, NOT full Adblock filter evaluation or a novelty proof.
Run with Python 3 standard library; --help lists the pinned input arguments.
"""
import argparse,csv,gzip,hashlib,json,re,shutil,statistics
from collections import Counter
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit
from datetime import datetime,timezone

def digest(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def norm_host(h):
    h=h.strip().lower().rstrip('.')
    try:return h.encode('idna').decode('ascii')
    except UnicodeError:return ''

def pure_host(h):
    return '.' in h and len(h)<=253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',s) for s in h.split('.'))

def suffixes(h):
    p=h.split('.')
    return ['.'.join(p[i:]) for i in range(len(p))]

class HostList:
    def __init__(self,lines):
        self.raw=[s.strip().lower() for s in lines if s.strip() and not s.startswith('!')]
        self.exact=set(s for s in self.raw if pure_host(s))
        self.non_host=[s for s in self.raw if s not in self.exact]
        self.potential=[]
        for raw in self.non_host:
            pattern=raw.split('$',1)[0]
                                                                            
                                                                              
            if '*plvid=' in pattern:pattern=pattern.split('*plvid=',1)[0]
            if pattern.endswith('.'):pattern+='*'
            rx=re.compile(r'^(?:[^.]+\.)*'+re.escape(pattern).replace(r'\*','.*')+'$')
            self.potential.append((raw,rx))

    @lru_cache(maxsize=None)
    def match(self,h):
        h=norm_host(h)
        exact=tuple(s for s in suffixes(h) if s in self.exact) if h else ()
        possible=tuple(raw for raw,rx in self.potential if rx.fullmatch(h)) if h else ()
        return exact,possible

def tracker_hosts(s):
                                                                           
    result=set()
    for x in (s or '').split('|'):
        x=x.strip()
        if not x or x in ('None','N/A','-'):continue
        host=urlsplit(x if '://' in x else '//'+x).hostname
        assert host,('Invalid observed tracker netloc',x)
        result.add(norm_host(host))
    return result

def write_csv(path,rows,fields):
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
    with path.open(encoding='utf-8-sig',newline='') as f:assert sum(1 for _ in csv.DictReader(f))==len(rows)

def audit_old(path,ls,out):
    by={};mismatches=[];examples=[]
    with path.open(encoding='utf-8-sig',newline='') as f:
        for r in csv.DictReader(f):
            label=(r.get('Tracker_Class') or '').strip()
            if label not in ('Mixed Tracker - Known','Mixed Tracker - Unknown'):continue
            dom=r['Domain'];obs=tracker_hosts(r.get('Observed_Trackers'))
            a=by.setdefault(dom,dict(known=False,unknown=False,obs=set()))
            a['known']|=label.endswith('Known');a['unknown']|=label.endswith('Unknown');a['obs']|=obs
            if label.endswith('Known') and obs and not any(ls.match(h)[0] for h in obs) and len(examples)<15:
                examples.append(dict(domain=dom,observed_hosts=sorted(obs),known_tracker_domains=r.get('Known_Tracker_Domains')))
    counts=Counter();delta=[]
    for dom,r in sorted(by.items()):
        observed=any(ls.match(h)[0] for h in r['obs']);target=bool(ls.match(dom)[0])
        counts['recorded_known' if r['known'] else 'recorded_novel']+=1
        counts['recomputed_known_observed_or_target' if observed or target else 'recomputed_no_literal_match']+=1
        counts['both_recorded_labels']+=int(r['known'] and r['unknown'])
        if r['known']!=(observed or target):
            delta.append(dict(Domain=dom,Recorded_Known=int(r['known']),Literal_Match_Observed=int(observed),Literal_Match_Target=int(target),Observed_Tracker_Hosts=' | '.join(sorted(r['obs']))))
    write_csv(out/'historical_comparison_disagreements.csv',delta,['Domain','Recorded_Known','Literal_Match_Observed','Literal_Match_Target','Observed_Tracker_Hosts'])
    return dict(domains=len(by),counts=dict(counts),disagreeing_domains=len(delta),examples=examples,old_procedure_reproduced=False,note='The archived list and literal matching do not reproduce the old labels. No assertion is made that this was the original list version or algorithm.')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--classification',type=Path,required=True)
    p.add_argument('--network-dir',type=Path,required=True)
    p.add_argument('--list',type=Path,required=True)
    p.add_argument('--old-csv',type=Path)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    assert not a.output.exists(),'Use a new output folder; never overwrite prior results.'
    paths=[a.classification,a.list,*[a.network_dir/(h+'_network.json.gz') for h in ['local','argus1','argus2','argus3']]]
    if a.old_csv:paths.append(a.old_csv)
    before={str(x.resolve()):digest(x) for x in paths}
    with gzip.open(a.classification,'rt',encoding='utf8') as f:cl=json.load(f)
    selected=[r for r in cl['rows'] if r['domain_finding']['matched'] and r['domain_finding']['valid_for_corrected_headline'] and r['findings']]
    assert len(selected)==len({r['domain'] for r in selected})==11124
    assert all(r['status']=='CLASSIFIED' and 3 in r['rule_numbers'] for r in selected)
    chosen={(r['domain'],r['wholepage_sha256']):r for r in selected}
    ls=HostList(a.list.read_text(encoding='utf-8-sig').splitlines())
                                                                          
    t=HostList(['tracker.example','sub.example.org','foo*.example.net','coin.test$third-party'])
    assert t.match('a.tracker.example')[0]==('tracker.example',)
    assert t.match('tracker.example.evil.test')[0]==()
    assert t.match('nottracker.example')[0]==()
    assert t.match('example.org')[0]==()
    assert t.match('a.sub.example.org')[0]==('sub.example.org',)
    assert t.match('foo1.example.net')[0]==() and t.match('foo1.example.net')[1]
    assert t.match('coin.test')[0]==() and t.match('coin.test')[1]
    assert tracker_hosts('54.151.247.122:15212 | www.example.com:443')=={'54.151.247.122','www.example.com'}
    a.output.mkdir(parents=True)
    shutil.copy2(a.list,a.output/'archived_easyprivacy_tracker_domains.txt')
    shutil.copy2(Path(__file__),a.output/Path(__file__).name)
    write_csv(a.output/'non_hostname_entries.csv',[{'Entry':x,'Handling':'POTENTIAL_MATCH_ONLY_NOT_FULL_FILTER_EVALUATION'} for x in ls.non_host],['Entry','Handling'])
    rows=[];evidence=[];seen=set();network_counts={};failures=[]
    for host in ['local','argus1','argus2','argus3']:
        with gzip.open(a.network_dir/(host+'_network.json.gz'),'rt',encoding='utf8') as f:net=json.load(f)
        network_counts[host]=len(net)
        for n in net:
            key=n['domain'],n['wholepage_sha256']
            if key not in chosen:continue
            assert key not in seen,'Duplicate network input identity'
            seen.add(key);r=chosen[key];urls=n['urls']
            actual=hashlib.sha256(json.dumps(urls,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
            assert actual==n['urls_sha256']==r['network_urls_sha256'],'Network hash identity mismatch'
            hosts=Counter();bad=0
            for u in urls:
                try:
                    v=urlsplit(u);h=norm_host(v.hostname or '')
                    if v.scheme not in ('http','https') or not h:bad+=1;continue
                    hosts[h]+=1
                except ValueError:bad+=1
            literal={h:ls.match(h)[0] for h in hosts if ls.match(h)[0]}
            potential={h:ls.match(h)[1] for h in hosts if ls.match(h)[1]}
            target_literal,target_potential=ls.match(r['domain'])
            obs=set(h for f in r['findings'] for h in tracker_hosts(f['Observed_Trackers']))
            obs_hits={h for h in obs if ls.match(h)[0]}
            obs_unseen=obs-set(hosts)
            assert not obs_unseen,('Observed tracker outside pinned network',r['domain'],obs_unseen)
            network_complete=bool(n.get('drain_complete')) and n.get('pending_at_cutoff')==0
            if literal or target_literal:status='LIST_MATCHED'
            elif potential or target_potential:status='INDETERMINATE_NON_HOST_FILTER'
            elif not hosts:status='INDETERMINATE_NO_REQUEST_HOSTS'
            elif bad or not network_complete:status='INDETERMINATE_INCOMPLETE_NETWORK'
            else:status='NO_LIST_MATCH_OBSERVED'
            fields=dict(Domain=r['domain'],Status=status,Target_List_Matches=' | '.join(target_literal),Matched_Request_Host_Count=len(literal),Matched_Request_Hosts=' | '.join(sorted(literal)),Matched_List_Entries=' | '.join(sorted({q for v in literal.values() for q in v})),Potential_Non_Host_Entries=' | '.join(sorted(set(target_potential)|{q for v in potential.values() for q in v})),Observed_Tracker_Host_Count=len(obs),Observed_Tracker_List_Match=int(bool(obs_hits)),Request_URL_Count=len(urls),Request_Host_Count=len(hosts),Network_Drain_Complete=int(network_complete),Crawl_Status=n.get('crawl_status'),Malformed_URL_Count=bad,Finding_Groups=len(r['findings']),Max_Score=max(int(f['Confidence_Score']) for f in r['findings']),Host=host,Wholepage_SHA256=r['wholepage_sha256'],Network_URLs_SHA256=actual,Visit_Manifest_SHA256=n['manifest_sha256'])
            rows.append(fields)
            for h,entries in literal.items():
                evidence.append(dict(Domain=r['domain'],Evidence_Source='SAVED_REQUEST_HOST',Observed_Host=h,List_Entries=' | '.join(entries),Saved_URL_Count=hosts[h],Network_URLs_SHA256=actual))
            if target_literal:evidence.append(dict(Domain=r['domain'],Evidence_Source='TARGET_HOST',Observed_Host=r['domain'],List_Entries=' | '.join(target_literal),Saved_URL_Count=0,Network_URLs_SHA256=actual))
        print(json.dumps(dict(host=host,selected_processed=len(rows)),ensure_ascii=True),flush=True)
    assert set(chosen)==seen,'Missing selected input/network identities'
    rows.sort(key=lambda r:r['Domain']);fields=list(rows[0])
    write_csv(a.output/'all_11124_domain_comparison.csv',rows,fields)
    unlisted=[r for r in rows if r['Status']=='NO_LIST_MATCH_OBSERVED']
    unknown=[r for r in rows if r['Status'].startswith('INDETERMINATE')]
    write_csv(a.output/'unlisted_mixed_candidates.csv',unlisted,fields)
    write_csv(a.output/'indeterminate_candidates.csv',unknown,fields)
    write_csv(a.output/'matched_host_evidence.csv',sorted(evidence,key=lambda r:(r['Domain'],r['Evidence_Source'],r['Observed_Host'])),['Domain','Evidence_Source','Observed_Host','List_Entries','Saved_URL_Count','Network_URLs_SHA256'])
    old=audit_old(a.old_csv,ls,a.output) if a.old_csv else None
    statuses=Counter(r['Status'] for r in rows)
    csv_paths=list(a.output.glob('*.csv'))
    result=dict(status='PASS',created_at_utc=datetime.now(timezone.utc).isoformat(),cohort='corrected R3 AND at least one independent R1/R2/R4/R5 finding',cohort_domains=len(rows),finding_groups=sum(r['Finding_Groups'] for r in rows),list=dict(source=str(a.list.resolve()),sha256=digest(a.list),lines=len(ls.raw),literal_hostname_entries=len(ls.exact),non_hostname_entries=len(ls.non_host),official_version_date=None,interpretation='Locally archived EasyPrivacy-derived host list; upstream date and extraction provenance not established'),classification_counts=dict(statuses),percent_of_cohort={k:100*v/len(rows) for k,v in statuses.items()},matching='Exact hostname or dot-boundary subdomain suffix against literal hostname entries, on target hostname OR all pinned saved HTTP(S) request hostnames. Includes same-site requests; not third-party-only and not full Adblock filtering.',historical_comparison=old,sensitivity=dict(filtered_observed_tracker_field_matches=sum(r['Observed_Tracker_List_Match'] for r in rows),filtered_observed_tracker_field_no_matches=sum(not r['Observed_Tracker_List_Match'] for r in rows),no_filtered_observed_tracker_hosts=sum(not r['Observed_Tracker_Host_Count'] for r in rows),unlisted_with_filtered_tracker_hosts=sum(bool(r['Observed_Tracker_Host_Count']) for r in unlisted),unlisted_without_filtered_tracker_hosts=sum(not r['Observed_Tracker_Host_Count'] for r in unlisted),target_listed_domains=sum(bool(r['Target_List_Matches']) for r in rows),network_listed_domains=sum(bool(r['Matched_Request_Host_Count']) for r in rows)),network_inputs_per_host=network_counts,unlisted_max_score_counts=dict(Counter(r['Max_Score'] for r in unlisted)),unlisted_finding_groups=sum(r['Finding_Groups'] for r in unlisted),original_files_preserved=all(digest(Path(p))==h for p,h in before.items()),inputs_sha256=before,output_csv_sha256={p.name:digest(p) for p in csv_paths},matching_boundary_tests='PASS',native_or_crawler_runs=0,limitations=['No assertion of previously unknown tracker, confirmed tracking, or original-paper-comparable count.','Absence of matching saved request hosts does not establish absence of tracking or absence from all EasyPrivacy URL rules.','Archived list date/extraction procedure unknown; 29 non-host entries are screened conservatively, not evaluated as full filter rules.','All observed request hosts are tested, without a third-party/PSL filter or proof of route-to-request causation.','Existing UNKNOWN route/context semantics remain unchanged.','Partial crawl flags are retained even when network drain completed.'])
    assert result['original_files_preserved'] and sum(statuses.values())==11124
    (a.output/'comparison_summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:result[k] for k in ['status','classification_counts','percent_of_cohort','sensitivity','unlisted_finding_groups','unlisted_max_score_counts','original_files_preserved']},ensure_ascii=True,indent=2))

if __name__=='__main__':main()
