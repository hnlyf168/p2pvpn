from pathlib import Path
import tarfile,hashlib,json
root=Path.cwd();dest=root/'artifacts/native-0.3.3/source.tar.gz'
dest.parent.mkdir(parents=True,exist_ok=True)
with tarfile.open(dest,'w:gz') as tar:
 for folder in ('src/Client','src/Transport'):
  for f in (root/folder).rglob('*'):
   if not f.is_file() or any(x in ('obj','bin','data','.git') for x in f.relative_to(root).parts):continue
   if f.name=='client.json' or f.suffix in ('.pdb','.env','.log'):continue
   rel=f.relative_to(root).as_posix();info=tar.gettarinfo(str(f),rel);info.uid=info.gid=0;info.uname=info.gname='root';info.mode=0o644
   with f.open('rb') as stream:tar.addfile(info,stream)
print('Source archive:',dest.stat().st_size,'bytes; SHA256',hashlib.sha256(dest.read_bytes()).hexdigest())
