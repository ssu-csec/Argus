"""Bounded, lossless native stdout transport; no engine or input rewriting."""
import gzip, hashlib, json, os, subprocess, sys
from pathlib import Path

BLOCK=64*1024
RAW_LIMIT=1024**3
FILE_LIMIT=256*1024**2

def verify(path, receipt):
    assert receipt['eof'] and receipt['verified'], 'UNSEALED_STREAM'
    h=hashlib.sha256(); n=0
    with gzip.open(path,'rb') as f:
        for b in iter(lambda:f.read(BLOCK),b''):
            n+=len(b)
            assert n<=RAW_LIMIT, 'LOGICAL_OUTPUT_LIMIT'
            h.update(b)
    assert n==receipt['raw_bytes'] and h.hexdigest()==receipt['raw_sha256'], 'STREAM_MISMATCH'
    assert Path(path).stat().st_size<=FILE_LIMIT
    return n

def main():
    dest=Path(sys.argv[1]); command=sys.argv[2:]
    assert command and not dest.exists()
    h=hashlib.sha256(); n=0; p=None; receipt={'eof':False,'verified':False}
    try:
        p=subprocess.Popen(command,stdout=subprocess.PIPE,stdin=subprocess.DEVNULL)
        with dest.open('xb') as raw:
            with gzip.GzipFile(fileobj=raw,mode='wb',compresslevel=1,mtime=0) as out:
                while True:
                    b=p.stdout.read(BLOCK)
                    if not b: break
                    n+=len(b)
                    if n>RAW_LIMIT: raise RuntimeError('LOGICAL_OUTPUT_LIMIT')
                    h.update(b);out.write(b)
                    if raw.tell()>FILE_LIMIT: raise RuntimeError('COMPRESSED_OUTPUT_LIMIT')
            raw.flush();os.fsync(raw.fileno())
        rc=p.wait()
        receipt.update(eof=True,verified=True,raw_bytes=n,raw_sha256=h.hexdigest(),native_returncode=rc,compressed_bytes=dest.stat().st_size)
        verify(dest,receipt)
        receipt['compressed_sha256']=hashlib.sha256(dest.read_bytes()).hexdigest()
        dest.with_suffix('.receipt.json').write_text(json.dumps(receipt,indent=2))
        return rc if rc>=0 else 128-rc
    except Exception as e:
        receipt.update(verified=False,error=repr(e),raw_bytes=n)
        dest.with_suffix('.error.json').write_text(json.dumps(receipt,indent=2))
        return 70
    finally:
        if p is not None and p.poll() is None:p.kill();p.wait()

if __name__=='__main__':sys.exit(main())
