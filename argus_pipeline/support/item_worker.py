"""Bounded subprocess execution extracted unchanged from the verified worker."""
import hashlib,json,os,shutil,signal,subprocess,time
from pathlib import Path
MIB=1024**2

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for b in iter(lambda: stream.read(MIB), b''): h.update(b)
    return h.hexdigest()

def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def put(path, value):
    with Path(path).open('x', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2); f.write('\n')
        f.flush(); os.fsync(f.fileno())

def require(test, reason):
    if not test: raise ValueError(reason)

def tree_bytes(root):
                                                           
    seen, total = set(), 0
    for p in Path(root).rglob('*'):
        if p.is_file() and not p.is_symlink():
            s = p.stat(); key = (s.st_dev, s.st_ino)
            if key not in seen: total += s.st_size; seen.add(key)
    return total

def child(command, cwd, logs, timeout, config, env, budget_dir, notify):
    logs.mkdir(parents=True, exist_ok=True)
    executable = shutil.which('prlimit')
    require(executable, 'PRLIMIT_UNAVAILABLE')
    file_mib=config.get('file_limit_mib',256)
    item_mib=config.get('item_limit_mib',512)
    reserve_gib=config.get('reserve_disk_gib',20)
    require(type(file_mib) is int and 1 <= file_mib <= 2048, 'INVALID_FILE_LIMIT')
    require(type(item_mib) is int and file_mib <= item_mib <= 4096, 'INVALID_ITEM_LIMIT')
    require(type(reserve_gib) is int and reserve_gib >= 10, 'INVALID_DISK_RESERVE')
    cmd = [executable, '--as=' + str(int(config.get('memory_gib', 8) * 1024**3)),
           '--fsize=' + str(file_mib * MIB), '--core=0', '--', *map(str, command)]
    result = {'command': cmd, 'returncode': None, 'stop_reason': None, 'error': None,
              'started': False, 'pins_preserved': False}
    started = time.monotonic(); proc = None
    try:
        with (logs/'stdout.log').open('xb') as out, (logs/'stderr.log').open('xb') as err:
            proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=err, start_new_session=True)
            result.update(started=True, pid=proc.pid)
            stat = Path(f'/proc/{proc.pid}/stat').read_text()
            put(logs/'process.json', {'pid': proc.pid, 'pgid': proc.pid, 'parent_pid': os.getpid(),
                'start_ticks': stat[stat.rfind(')') + 2:].split()[19], 'command': cmd, 'cwd': str(cwd)})
            notify('CHILD_STARTED')
            while proc.poll() is None:
                if time.monotonic() - started >= timeout: result['stop_reason'] = 'TIMEOUT'
                elif tree_bytes(budget_dir) >= item_mib * MIB: result['stop_reason'] = 'OUTPUT_LIMIT'
                elif shutil.disk_usage(budget_dir).free < reserve_gib * 1024**3: result['stop_reason'] = 'LOW_DISK'
                if result['stop_reason']:
                    try: os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    break
                time.sleep(0.1)
            result['returncode'] = proc.wait()
            out.flush(); err.flush(); os.fsync(out.fileno()); os.fsync(err.fileno())
    except Exception as error:
        result['error'] = repr(error)
    finally:
        if proc is not None and proc.poll() is None:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait()
        if proc is not None: result['returncode'] = proc.returncode
    result['seconds'] = round(time.monotonic() - started, 6)
    if tree_bytes(budget_dir) >= item_mib * MIB: result['stop_reason'] = result['stop_reason'] or 'OUTPUT_LIMIT'
    result['status'] = result['stop_reason'] or ('OK' if result['returncode'] == 0 and not result['error'] else 'EXECUTION_ERROR' if result['error'] else 'EXIT_' + str(result['returncode']))
    return result
