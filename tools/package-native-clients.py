from pathlib import Path
import tarfile,zipfile,struct,json,hashlib,shutil,subprocess
root=Path.cwd();version='0.3.3';reports=[]
def inspect_elf(data):
 assert data[:4]==b'\x7fELF' and data[5]==1
 bits=32 if data[4]==1 else 64
 machine=struct.unpack_from('<H',data,18)[0]
 phoff=struct.unpack_from('<I' if bits==32 else '<Q',data,28 if bits==32 else 32)[0]
 phsize,phcount=struct.unpack_from('<HH',data,42 if bits==32 else 54)
 needed=[];interp=False
 for i in range(phcount):
  at=phoff+i*phsize;kind=struct.unpack_from('<I',data,at)[0]
  if kind==3:interp=True
  if kind==2:
   offset=struct.unpack_from('<I' if bits==32 else '<Q',data,at+4 if bits==32 else at+8)[0]
   size=struct.unpack_from('<I' if bits==32 else '<Q',data,at+16 if bits==32 else at+32)[0]
   stride=8 if bits==32 else 16
   for pos in range(offset,offset+size,stride):
    tag,val=struct.unpack_from('<II' if bits==32 else '<QQ',data,pos)
    if tag==0:break
    if tag==1:needed.append(val)
 assert not interp and not needed, 'Binary is not fully static'
 return {'bits':bits,'machine':machine,'PT_INTERP':interp,'DT_NEEDED':needed}
for arch,machine in [('x64',62),('arm64',183),('arm',40)]:
 rid='linux-musl-'+arch;target=root/'artifacts/releases'/version/('client-linux-'+arch);target.mkdir(parents=True,exist_ok=True)
 with tarfile.open(root/'artifacts/native-0.3.3'/(rid+'.tar.gz')) as tar:
  tar.extractall(target,filter='data')
 shutil.copy2(root/'src/Client/README.md',target/'README.md')
 data=(target/'P2PVpnClient').read_bytes();elf=inspect_elf(data);assert elf['machine']==machine
 archive=root/'artifacts/downloads'/('edge-vpn-client-linux-'+arch+'-'+version+'.zip')
 archive.parent.mkdir(parents=True,exist_ok=True)
 subprocess.run(['python','tools/zip-package.py',str(target),str(archive),'--client'],check=True)
 shutil.copy2(archive,root/'src/ControlPlane/downloads'/archive.name)
 reports.append({'platform':'linux-'+arch,**elf,'sha256':hashlib.sha256(data).hexdigest(),'binarySize':len(data),'package':archive.name,'packageSha256':hashlib.sha256(archive.read_bytes()).hexdigest()})
(root/'artifacts/native-0.3.3/verified.json').write_text(json.dumps(reports,indent=2),encoding='utf-8');print(json.dumps(reports,indent=2))
