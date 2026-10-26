import gzip

def assess_verified(path, complete, routes, assessor):
    if not complete:
        return assessor([], False, routes)
    observations=[]
    evidence={k:[]for k in ['execution','conditional_routes','unexecuted_candidates','unconfirmed_candidates']}
    tags={'[NATIVE_GENERATOR_EXECUTION]':'execution','[NATIVE_CONDITIONAL_ROUTE]':'conditional_routes','[NATIVE_UNEXECUTED_CANDIDATE]':'unexecuted_candidates','[NATIVE_UNCONFIRMED_CANDIDATE]':'unconfirmed_candidates'}
    def lines(stream):
        for line in stream:
            if line.startswith('[NATIVE_STATIC_RETURN_TRANSPORT]') and 'status=CONDITIONAL' in line:
                observations.append(line.strip())
            for tag,key in tags.items():
                if line.startswith(tag):evidence[key].append(line.strip())
            yield line
    with gzip.open(path,'rt',errors='replace')as stream:
        iterator=lines(stream)
        result=assessor(iterator,True,routes)
                                                                          
                                                                             
        for unused in iterator:
            pass
    if observations:
        result['semantic_status']='UNKNOWN'
        result['negative_inference_allowed']=False
        result['site_benign_inference_allowed']=False
        result.setdefault('unknown_reasons',[]).append('CONDITIONAL_NATIVE_STATIC_RETURN_ENVIRONMENT_UNPROVEN')
        result['conditional_return_observations']=observations
    if evidence['execution']:
        conditional=any('status=CONDITIONAL'in s for s in evidence['execution'])
        result['generator_execution_evidence']=dict(**evidence,environment='UNPROVEN',negative_certificate=False,raw_potential_routes_preserved=True,conditional_route_count=len(evidence['conditional_routes'])if conditional else None,unexecuted_candidate_count=len(evidence['unexecuted_candidates'])if conditional else None,unconfirmed_candidate_count=len(evidence['unconfirmed_candidates'])if conditional else None)
    return result

_base_assess_verified = assess_verified
def assess_verified(path, complete, routes, assessor):
    result = _base_assess_verified(path, complete, routes, assessor)
    if complete:
        with gzip.open(path, 'rt', errors='replace') as stream:
            evidence = [line.strip() for line in stream if line.startswith('[ORDINARY_RETURN_TRANSPORT]')]
        result['ordinary_return_evidence'] = evidence
        if any('status=UNKNOWN' in line for line in evidence):
            result['semantic_status'] = 'UNKNOWN'
            result['negative_inference_allowed'] = False
            result['site_benign_inference_allowed'] = False
            result.setdefault('unknown_reasons', []).append('ORDINARY_RETURN_TRANSPORT_UNKNOWN')
    return result
