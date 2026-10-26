import re
SEMANTIC_TAGS=('NATIVE_PRIVATE_SCALAR_STATE','PRIVATE_METHOD_COMPLETION','PRIVATE_ADDITIVE_PREFIX')
def assess(lines,native_complete,routes,scope_coverage_verified=False):
 observations=[];unknown=[];normal=False
 for raw in lines:
  if not raw.startswith(tuple('['+t+']'for t in SEMANTIC_TAGS)):continue
  line=raw.strip();observations.append(line)
  if line.startswith('[PRIVATE_METHOD_COMPLETION]')and 'status=NORMAL 'in line:normal=True
  if 'status=UNKNOWN'in line:
   m=re.search(r'reason=([^\s]+)',line);unknown.append(m[1]if m else'UNSPECIFIED_UNKNOWN')
 if not native_complete:return dict(native_complete=False,semantic_status='NOT_EVALUATED',negative_inference_allowed=False,unknown_reasons=sorted(set(unknown)),observations=observations)
 if unknown:status='UNKNOWN'
 elif routes and routes>0:status='FLOW_REPORTED'
 elif normal and scope_coverage_verified:status='NO_FLOW_PROVED_IN_BOUNDED_SCOPE'
 elif normal:status='UNKNOWN';unknown=['NO_SCOPE_COVERAGE_CERTIFICATE']
 else:status='UNKNOWN';unknown=['NO_NORMAL_COMPLETION_CERTIFICATE']
 return dict(native_complete=True,semantic_status=status,negative_inference_allowed=status=='NO_FLOW_PROVED_IN_BOUNDED_SCOPE',site_benign_inference_allowed=False,unknown_reasons=sorted(set(unknown)),reported_routes=routes,observations=observations)
