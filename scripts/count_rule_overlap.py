from pathlib import Path
from collections import Counter
import gzip, json, hashlib, re, argparse

parser = argparse.ArgumentParser(description='Reproduce historical rule overlap by unique domain.')
parser.add_argument('--input', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
if args.output.exists():
    parser.error('--output must be a new file')
source = args.input
blob = source.read_bytes()
data = json.loads(gzip.decompress(blob))
rows = data['rows']
assert len(rows) == len({r['domain'] for r in rows}) == 44882
sets = []
for r in rows:
    rules = {int(n) for f in r['findings'] for n in re.findall(r'Rule ([1245])', f['Threat_Type'])}
    if r['domain_finding']['matched'] and r['domain_finding']['valid_for_corrected_headline']:
        rules.add(3)
    assert rules == set(r['rule_numbers'])
    sets.append(rules)

def aggregate(allowed):
    selected = [s & set(allowed) for s in sets]
    combos = Counter(tuple(sorted(s)) for s in selected)
    totals = {f'R{n}': sum(n in s for s in selected) for n in allowed}
    counts = Counter(len(s) for s in selected)
    assert sum(combos.values()) == len(rows)
    assert sum(k*v for k,v in counts.items()) == sum(totals.values())
    return dict(
        rule_totals=totals,
        exact_combinations={'+'.join(f'R{n}' for n in k) or 'NONE': v for k,v in sorted(combos.items(), key=lambda kv:(len(kv[0]),kv[0]))},
        number_of_rules=dict(sorted(counts.items())),
        exclusive={f'R{n}':combos[(n,)] for n in allowed},
        overlapping_per_rule={f'R{n}':sum(n in s and len(s)>1 for s in selected) for n in allowed},
        pairwise={f'R{a}+R{b}':sum({a,b}<=s for s in selected) for a in allowed for b in allowed if a<b},
        any_rule=sum(bool(s) for s in selected),
        multiple_rules=sum(len(s)>1 for s in selected),
    )

all_five = aggregate([1,2,3,4,5])
independent = aggregate([1,2,4,5])
assert independent['any_rule'] == data['summary']['rule_matched_domains'] == 33096
for r in data['summary']['rules']:
    assert all_five['rule_totals'][r['rule']] == r['domains']
assert all_five['exclusive']['R3'] == 28
result = dict(status='PASS', unit='unique domain; simultaneous rules can be on different routes/groups', input_sha256=hashlib.sha256(blob).hexdigest(), total_domains=len(rows), all_five=all_five, independent_four=independent)
args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(result,ensure_ascii=False,indent=2))
