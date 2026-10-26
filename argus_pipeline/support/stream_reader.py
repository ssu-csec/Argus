"""Validate exact-input capture, complete IR output and native route schema."""
import gzip,hashlib,json,re
from pathlib import Path
MIB=1024**2

def load(path):
    with Path(path).open(encoding='utf-8') as stream:
        return json.load(stream)

def sha(path):
    digest = hashlib.sha256()
    with (gzip.open(Path(path).parent/'native.stdout.gz', 'rb') if Path(path).name=='stdout.log' else Path(path).open('rb')) as stream:
        for block in iter(lambda: stream.read(MIB), b''):
            digest.update(block)
    return digest.hexdigest()

def check(condition, message):
    if not condition:
        raise RuntimeError(message)

def bounded_lines(path, prefix_limit=4096):
    """Stream arbitrarily long source/IR lines, retaining only each prefix."""
    prefix = bytearray()
    with (gzip.open(Path(path).parent/'native.stdout.gz', 'rb') if Path(path).name=='stdout.log' else Path(path).open('rb')) as stream:
        for block in iter(lambda: stream.read(64 * 1024), b''):
            parts = block.split(b'\n')
            for index, part in enumerate(parts):
                if len(prefix) < prefix_limit:
                    prefix.extend(part[:prefix_limit - len(prefix)])
                if index != len(parts) - 1:
                    yield bytes(prefix).decode('utf-8', errors='replace').rstrip('\r')
                    prefix.clear()
        if prefix:
            yield bytes(prefix).decode('utf-8', errors='replace').rstrip('\r')

def inspect_logs(directory):
    markers = ends = 0
    private = []
    diagnostics = []
    errors = 0
    for line in bounded_lines(directory / 'stdout.log'):
        if line.strip() == '=== Taint Analysis Complete':
            markers += 1
        if re.match(r'^\s*function_end\b', line):
            ends += 1
        if line.startswith('[PRIVATE_') and len(private) < 256:
            private.append(line)
    for line in bounded_lines(directory / 'stderr.log'):
        if ': error:' in line or re.match(r'^\s*(?:error|fatal error):', line):
            errors += 1
            if len(diagnostics) < 128:
                diagnostics.append(line)
    return {'taint_completion_markers': markers, 'ir_function_end_count': ends,
            'stderr_error_header_count': errors, 'diagnostics': diagnostics,
            'private_diagnostics': private}

def valid_location(value):
    return (isinstance(value, dict) and
            type(value.get('line')) is int and value['line'] >= 0 and
            type(value.get('column')) is int and value['column'] >= 0)

def report_data(directory):
    candidates = sorted((directory / 'report').rglob('*report.json'))
    check(len(candidates) == 1, 'REPORT_MISSING_OR_NONUNIQUE')
    path = candidates[0]
    check(path.is_file() and path.stat().st_size <= 512 * MIB, 'REPORT_SIZE_LIMIT')
    document = load(path)
    check(isinstance(document, dict) and isinstance(document.get('s2s_routes'), list),
          'INVALID_REPORT_SCHEMA')
    routes = document['s2s_routes']
    identities = set()
    for route in routes:
        check(isinstance(route, dict), 'INVALID_ROUTE')
        route_id = route.get('route_id')
        check(type(route_id) is int and route_id not in identities, 'INVALID_ROUTE_ID')
        identities.add(route_id)
        check(isinstance(route.get('source_name'), str) and
              isinstance(route.get('sink_name'), str) and
              valid_location(route.get('source_location')) and
              valid_location(route.get('sink_location')) and
              isinstance(route.get('path_nodes'), list), 'INVALID_ROUTE_SCHEMA')
        check(all(isinstance(node, str) and node for node in route['path_nodes']), 'INVALID_PATH_NODE')
    return path, routes

def route_pairs(routes, date_cookie=False):
    result = []
    for route in routes:
        if date_cookie and (route['source_name'] not in ('Date', 'Date.now') or
                            route['sink_name'] != 'document.cookie'):
            continue
        source, sink = route['source_location'], route['sink_location']
        result.append([route['source_name'], source['line'], source['column'],
                       route['sink_name'], sink['line'], sink['column']])
                                                                           
    return sorted(result)

def analyze(row, directory, end):
    output = dict(row)
    output.update({'execution': end, 'analysis_complete': False,
                   'capture_exact_match': False, 'valid_report': False,
                   'report_path': None, 'report_sha256': None, 'routes': None,
                   'total_emitted_routes': None, 'date_cookie_emitted_route_count': None,
                   'all_pairs': None, 'date_cookie_pairs': None,
                   'semantic_labels_assigned': False, 'whole_site_recovery': False,
                   'projection_scope': 'RAW_CONCATENATED_INPUT' if row['arm'] == 'raw_base'
                   else 'PARTIAL_DATA_RESPONSE_PROJECTION', 'validation_errors': []})
    try:
        metadata = load(directory / 'captured.metadata.json')
        count = Path(row['source']).stat().st_size
        capture_ok = (metadata.get('capture_complete') is True and
                      metadata.get('direct_file_only') is True and
                      metadata.get('capture_only') is False and
                      metadata.get('legacy_suffix_applied') is False and
                      metadata.get('buffer_terminator_included') is False and
                      metadata.get('before_bytes') == count == metadata.get('after_bytes') and
                      sha(directory / 'captured.before.bin') == row['sha256'] and
                      sha(directory / 'captured.after.bin') == row['sha256'] and
                      sha(row['source']) == row['sha256'])
        output['capture_metadata'] = metadata
        output['capture_exact_match'] = capture_ok
        check(capture_ok, 'CAPTURE_CONTRACT_MISMATCH')
    except Exception as error:
        output['validation_errors'].append('CAPTURE: ' + repr(error))
    try:
        output.update(inspect_logs(directory))
    except Exception as error:
        output['validation_errors'].append('LOG: ' + repr(error))
    routes = None
    try:
        report, routes = report_data(directory)
        output.update({'valid_report': True, 'report_path': str(report),
                       'report_sha256': sha(report)})
    except Exception as error:
        output['validation_errors'].append('REPORT: ' + repr(error))
    complete = (end.get('returncode') == 0 and not end.get('stop_reason') and
                not end.get('error') and end.get('pins_preserved') is True and
                output['capture_exact_match'] and output['valid_report'] and
                output.get('taint_completion_markers') == 1 and
                output.get('ir_function_end_count', 0) > 0 and
                output.get('stderr_error_header_count') == 0)
    if complete:
        output.update({'analysis_complete': True, 'status': 'COMPLETE', 'routes': routes,
                       'total_emitted_routes': len(routes),
                       'date_cookie_emitted_route_count': len(route_pairs(routes, True)),
                       'all_pairs': route_pairs(routes), 'date_cookie_pairs': route_pairs(routes, True)})
    elif end.get('stop_reason'):
        output['status'] = end['stop_reason']
    elif end.get('error') or end.get('returncode') is None:
        output['status'] = 'EXECUTION_ERROR'
    elif end['returncode'] < 0:
        output['status'] = 'SIGNAL_' + str(-end['returncode'])
    elif end['returncode'] == 2:
        output['status'] = 'PARSER_OR_VALIDATION_ERROR'
    elif end['returncode'] != 0:
        output['status'] = 'EXIT_' + str(end['returncode'])
    else:
        output['status'] = 'INCOMPLETE_OR_UNVERIFIED_OUTPUT'
    return output
