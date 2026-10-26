"""Read complete, hash-verified plain/gzip IR; never truncate or infer completeness."""
import gzip,hashlib,json
from pathlib import Path

MAX_RAW=1024**3
MAX_STORED=256*1024**2
def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb')as f:
  for b in iter(lambda:f.read(65536),b''):h.update(b)
 return h.hexdigest()

def read_ir(base,name,meta):
 base=Path(base);storage=meta.get('ir_storage')
 if storage is None:return (base/name).read_bytes()
 if storage.get('encoding')!='gzip' or storage.get('file')!=name+'.gz':raise ValueError('Unsupported IR storage')
 path=base/(name+'.gz');receipt_path=base/(name+'.receipt.json')
 if (type(storage.get('raw_bytes'))is not int or not 0<storage['raw_bytes']<=MAX_RAW or
     path.stat().st_size!=storage.get('compressed_bytes') or path.stat().st_size>MAX_STORED or
     digest(path)!=storage.get('compressed_sha256') or digest(receipt_path)!=storage.get('receipt_sha256')):
  raise ValueError('Compressed IR storage hash/size mismatch')
 receipt=json.loads(receipt_path.read_text())
 if (receipt.get('eof')is not True or receipt.get('verified')is not True or receipt.get('native_returncode')!=0 or
     receipt.get('raw_sha256')!=meta.get('ir_sha256') or
     any(receipt.get(k)!=storage.get(k)for k in ('raw_bytes','compressed_bytes','compressed_sha256'))):
  raise ValueError('Incomplete or inconsistent IR transport receipt')
 data=bytearray();h=hashlib.sha256()
 with gzip.open(path,'rb')as f:
  for b in iter(lambda:f.read(65536),b''):
   if len(data)+len(b)>storage['raw_bytes']:raise ValueError('IR expanded byte limit')
   h.update(b);data.extend(b)
 if len(data)!=storage['raw_bytes']or h.hexdigest()!=meta['ir_sha256']:raise ValueError('IR expanded hash/size mismatch')
                                                                                   
 return bytes(data)
