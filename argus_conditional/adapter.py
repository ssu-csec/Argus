"""Bounded post-native sidecar. Never executes source JS or updates native output."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

INPUT_LIMIT = 4 * 1024**2
OUTPUT_LIMIT = 32 * 1024**2
LOG_LIMIT = 64 * 1024
RSS_LIMIT_KIB = 1536 * 1024
PACKAGE = Path(__file__).resolve().parent

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for b in iter(lambda: stream.read(1024**2), b''):
            h.update(b)
    return h.hexdigest()

def save_new(path, data):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write('\n')

def _run_worker(command, output, env, timeout_seconds):
    """Isolated Node; bounded logs, wall time and sampled RSS plus V8 heap cap."""
    began = time.monotonic()
    peak = 0
    stopped = None
    stdout = output / 'worker.stdout.log'
    stderr = output / 'worker.stderr.log'
    limiter = shutil.which('prlimit')
    if limiter is None:
        raise FileNotFoundError('prlimit resource-limit wrapper is unavailable')
                                                                              
    executed_command = [limiter, '--core=0', f'--fsize={OUTPUT_LIMIT}', '--', *command]
    with stdout.open('xb') as out, stderr.open('xb') as err:
        process = subprocess.Popen(executed_command, stdout=out, stderr=err, env=env,
                                   start_new_session=True)
        try:
            while process.poll() is None:
                try:
                    for line in Path(f'/proc/{process.pid}/status').read_text().splitlines():
                        if line.startswith('VmRSS:'):
                            peak = max(peak, int(line.split()[1]))
                except FileNotFoundError:
                    pass
                if time.monotonic() - began > timeout_seconds:
                    stopped = 'TIMEOUT'
                elif peak > RSS_LIMIT_KIB:
                    stopped = 'MEMORY_LIMIT'
                elif stdout.stat().st_size > LOG_LIMIT or stderr.stat().st_size > LOG_LIMIT:
                    stopped = 'LOG_LIMIT'
                if stopped:
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(0.025)
            process.wait()
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    if stdout.stat().st_size > LOG_LIMIT or stderr.stat().st_size > LOG_LIMIT:
        stopped = stopped or 'LOG_LIMIT'
    return {'returncode': process.returncode, 'stop_reason': stopped, 'executed_command': executed_command,
            'seconds': round(time.monotonic() - began, 6), 'peak_rss_kib_sampled': peak,
            'stdout': str(stdout), 'stderr': str(stderr)}

def analyze_after_native(source, expected_sha256, output, native_record, *,
                         native_artifacts=(), unit_scope='EXACT_NATIVE_INPUT',
                         lineage=None, node='node', babel_root=None, timeout_seconds=15.0):
    """All auxiliary failures return an outcome; native_record is read-only.

    Caller supplies the exact source selected for native analysis. Lineage is
    caller metadata, not a semantic-equivalence or cross-script execution proof.
    """
    began = time.monotonic()
    source = Path(source).absolute()
    output = Path(output).absolute()
    native_artifacts = tuple(native_artifacts)
    snapshot = copy.deepcopy(native_record)
    result = {'schema': 'argus-pbjs-sidecar-v1', 'status': 'PENDING', 'reason': None,
              'source': str(source), 'expected_sha256': expected_sha256,
              'unit_scope': unit_scope, 'lineage': copy.deepcopy(lineage or {}),
              'lineage_semantic_equivalence_proved': False,
              'native_snapshot': snapshot, 'native_result_unchanged': True,
              'native_executions': 0, 'source_js_executions': 0,
              'prevalence_eligible': False, 'whole_site_recovery': False,
              'full_program_reachability_proved': False,
              'limits': {'input_bytes': INPUT_LIMIT, 'output_bytes': OUTPUT_LIMIT,
                         'timeout_seconds': timeout_seconds, 'v8_heap_mib': 768,
                         'rss_kib_sampled_limit': RSS_LIMIT_KIB, 'log_bytes': LOG_LIMIT},
              'output_directory': str(output), 'trace_path': None}
    pins = {}
    try:
        output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        result.update(status='OUTPUT_EXISTS', reason='Use a new output directory; partial results are not reused.')
        return result
    except OSError as error:
        result.update(status='OUTPUT_UNAVAILABLE', reason=str(error))
        return result
    try:
        if not 0 < timeout_seconds <= 60:
            result.update(status='INVALID_CONFIG', reason='timeout must be in (0, 60] seconds')
            return result
        for p in native_artifacts:
            p = Path(p).resolve(strict=True)
            pins[str(p)] = sha(p)
        if not isinstance(expected_sha256, str) or not re.fullmatch('[a-f0-9]{64}', expected_sha256):
            result.update(status='INPUT_HASH_MISMATCH', reason='Invalid expected SHA256')
            return result
        if not source.is_file():
            result.update(status='INPUT_UNAVAILABLE', reason='Source is not a regular file')
            return result
        if source.stat().st_size > INPUT_LIMIT:
            result.update(status='INPUT_SIZE_LIMIT', reason='Input exceeds 4 MiB; no parsing attempted')
            return result
        with source.open('rb') as stream:
            content = stream.read(INPUT_LIMIT + 1)
        if len(content) > INPUT_LIMIT:
            result.update(status='INPUT_SIZE_LIMIT', reason='Input grew beyond 4 MiB')
            return result
        result['observed_sha256'] = hashlib.sha256(content).hexdigest()
        if result['observed_sha256'] != expected_sha256:
            result.update(status='INPUT_HASH_MISMATCH', reason='Native-selected bytes differ from current bytes')
            return result
        pins[str(source.resolve())] = expected_sha256
        if b'pbjs' not in content:
            result.update(status='NOT_APPLICABLE', reason='No pbjs token for this bounded pass; not a benign verdict')
            return result
        executable = shutil.which(str(node))
        if executable is None:
            result.update(status='DEPENDENCY_UNAVAILABLE', reason='Node executable unavailable')
            return result
        target = output / 'trace.json'
        command = [executable, '--max-old-space-size=768', str(PACKAGE / 'js/worker.cjs'),
                   str(source.resolve()), str(target), expected_sha256]
        env = dict(os.environ)
                                                                          
        env.pop('NODE_OPTIONS', None)
        if babel_root is not None:
            env['ARGUS_BABEL_ROOT'] = str(babel_root)
        result['command'] = command
        result['node_sha256'] = sha(executable)
        result['adapter_sha256'] = sha(__file__)
        execution = _run_worker(command, output, env, timeout_seconds)
        result['execution'] = execution
        if execution['stop_reason']:
            result.update(status=execution['stop_reason'], reason='Conditional child stopped; native result retained')
            return result
        try:
            raw = Path(execution['stdout']).read_bytes()
            if len(raw) > LOG_LIMIT:
                raise ValueError('Worker response exceeds log limit')
            answer = json.loads(raw)
        except (OSError, ValueError) as error:
            result.update(status='WORKER_ERROR', reason=f'Invalid worker response: {error}')
            return result
        if execution['returncode'] != 0 or answer.get('status') != 'COMPLETE_CONDITIONAL_ANALYSIS':
            code = answer.get('code', 'WORKER_ERROR')
            status = 'DEPENDENCY_UNAVAILABLE' if code in ('BABEL_DEPENDENCY_MISSING', 'DEPENDENCY_METADATA_MISSING', 'MODULE_NOT_FOUND') else code
            if code == 'BABEL_PARSER_SYNTAX_ERROR':
                status = 'INPUT_PARSE_ERROR'
            result.update(status=status, worker_code=code, reason=answer.get('message', 'Worker failed'))
            return result
        if target.stat().st_size > OUTPUT_LIMIT or sha(target) != answer.get('outputSha256'):
            raise ValueError('WORKER_OUTPUT_INTEGRITY')
        data = json.loads(target.read_bytes())
        if data['sourceHash'] != expected_sha256 or data['sourceId'] != str(source.resolve()):
            raise ValueError('WORKER_SOURCE_IDENTITY')
        inv = data['trace']['invariants']
        if (inv['prevalenceCountEligible'] or inv['unconditionalReachedFlowCount'] != 0 or
                inv['unconditionalPrivateRecoveryCount'] != 0 or inv['runtimeExecutionObserved']):
            raise ValueError('CONDITIONAL_CONTRACT_CHANGED')
        observations = data['trace']['uniqueSourceSinkFieldObservations']
        result.update(status='COMPLETE_CONDITIONAL', reason='Conditional observations only',
                      trace_path=str(target), trace_sha256=answer['outputSha256'],
                      condition_variant_count=len(data['trace']['flows']),
                      unique_source_sink_field_count=len(observations),
                      observations=[{'source': g['source']['range']['loc']['start'],
                                     'sink': g['sink']['range']['loc']['start'], 'field': g['field'],
                                     'coordinate_basis': 'exact selected input; line 1-based, column 0-based',
                                     'statuses': g['statuses']} for g in observations],
                      guard_count=len(data['trace']['scenarios']),
                      cross_script_dispatch=data['trace']['siteToPublicApiDispatch'],
                      dependency_info=data['worker']['dependencies'])
    except Exception as error:
        result.update(status='INTEGRATION_ERROR', reason=f'{type(error).__name__}: {error}', trace_path=None)
    finally:
        changed = []
        for p, expected in pins.items():
            try:
                if sha(p) != expected:
                    changed.append(p)
            except OSError:
                changed.append(p)
        result['protected_pins'] = pins
        result['native_result_unchanged'] = native_record == snapshot and not any(str(Path(p).resolve()) in changed for p in native_artifacts)
        result['input_and_artifacts_unchanged'] = not changed
        if changed or native_record != snapshot:
            result.update(status='INTEGRITY_ERROR', reason='Protected input or native result changed',
                          changed_files=changed, trace_path=None)
        result['seconds'] = round(time.monotonic() - began, 6)
        try:
            save_new(output / 'summary.json', result)
        except OSError as error:
            result['summary_write_error'] = str(error)
    return result
