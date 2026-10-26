"""Attach conditional observations to an existing exact-input native run."""
import argparse
import json
from pathlib import Path
from .adapter import analyze_after_native, sha, save_new

def attach_native_run(native_run, output, **options):
    native_run = Path(native_run).resolve(strict=True)
    spec_path, analysis_path = native_run / 'spec.json', native_run / 'analysis.json'
    spec = json.loads(spec_path.read_text())
    analysis = json.loads(analysis_path.read_text())
    source = Path(analysis['source']).resolve(strict=True)
    expected = analysis['sha256']
                                                                                    
    if spec['command'][-1] != str(source) or spec['pins'].get(str(source)) != expected:
        raise ValueError('NATIVE_SELECTED_INPUT_MISMATCH')
    protected = [spec_path, analysis_path, native_run / 'execution.json',
                 native_run / 'captured.before.bin', native_run / 'captured.after.bin',
                 native_run / 'captured.identifier.txt']
    if (sha(protected[3]) != expected or sha(protected[4]) != expected or
            protected[5].read_text() != str(source) or analysis.get('capture_exact_match') is not True):
        raise ValueError('NATIVE_CAPTURE_MISMATCH')
    if analysis.get('report_path'):
        report = Path(analysis['report_path'])
        if sha(report) != analysis['report_sha256']:
            raise ValueError('NATIVE_REPORT_HASH_MISMATCH')
        protected.append(report)
    return analyze_after_native(source, expected, output, analysis,
                                native_artifacts=protected,
                                unit_scope='EXACT_CAPTURED_NATIVE_INPUT',
                                lineage={'native_run': str(native_run),
                                         'native_analysis_sha256': sha(analysis_path),
                                         'upstream_scope_as_reported': analysis.get('projection_scope'),
                                         'coordinate_basis': 'selected input only; original map not applied'},
                                **options)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native-run', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--node', default='node')
    p.add_argument('--babel-root')
    p.add_argument('--timeout', type=float, default=15)
    a = p.parse_args()
    try:
        r = attach_native_run(a.native_run, a.out, node=a.node,
                              babel_root=a.babel_root, timeout_seconds=a.timeout)
    except Exception as exc:
        r = {'status': 'NATIVE_BINDING_ERROR', 'reason': str(exc),
             'native_executions': 0, 'source_js_executions': 0, 'prevalence_eligible': False}
        try:
            a.out.mkdir(parents=True, exist_ok=False)
            save_new(a.out / 'summary.json', r)
        except OSError:
            pass
    print(json.dumps({k: r[k] for k in ('status', 'reason', 'trace_path',
          'unique_source_sink_field_count', 'condition_variant_count', 'seconds',
          'native_result_unchanged', 'native_executions') if k in r}, ensure_ascii=False))
    return 0 if r['status'] in ('COMPLETE_CONDITIONAL', 'NOT_APPLICABLE') else 2

if __name__ == '__main__':
    raise SystemExit(main())
