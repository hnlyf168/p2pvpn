from pathlib import Path
import shutil,tarfile,hashlib,json,subprocess,sys
version=sys.argv[1] if len(sys.argv)>1 else "0.3.2"
previous=sys.argv[2] if len(sys.argv)>2 else "0.3.1"
root=Path(__file__).resolve().parents[1]
release=root/'artifacts/releases'/version
app=release/'control-linux-x64'
old=root/'artifacts/releases'/previous/'control-linux-x64'
package=release/'control-package'
(package/'bin').mkdir(parents=True,exist_ok=True);(package/'deploy').mkdir(exist_ok=True)
for item in app.iterdir():
 if item.name in ('downloads','data') or item.suffix=='.pdb':continue
 target=package/'bin'/item.name
 if item.is_dir():shutil.copytree(item,target,dirs_exist_ok=True)
 else:shutil.copy2(item,target)
for name in ('control.env.example','edge-vpn-control.service','nginx.conf'):shutil.copy2(root/'deploy'/name,package/'deploy'/name)
shutil.copy2(root/'docs/DEPLOYMENT.md',package/'README.md')
zipfile=root/'artifacts/downloads'/('edge-vpn-control-linux-x64-'+version+'.zip')
subprocess.run(['python',str(root/'tools/zip-package.py'),str(package),str(zipfile)],check=True)
for dest in (app/'downloads',root/'src/ControlPlane/downloads'):
 dest.mkdir(exist_ok=True);shutil.copy2(zipfile,dest/zipfile.name)
out=root/('artifacts/deployment-v'+version.replace('.',''));out.mkdir(exist_ok=True)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def perms(t):
 t.uid=t.gid=0;t.uname=t.gname='root';t.mode=0o755 if t.isdir() or t.name=='EdgeVpn.ControlPlane' else 0o644;return t
changed=[]
with tarfile.open(out/('update-'+version+'.tar.gz'),'w:gz') as tar:
 for f in app.rglob('*'):
  if not f.is_file() or f.suffix=='.pdb':continue
  rel=f.relative_to(app)
  if rel.parts[0] in ('data','downloads'):continue
  prev=old/rel
  if prev.exists() and digest(prev)==digest(f):continue
  tar.add(f,arcname=rel.as_posix(),filter=perms);changed.append(rel.as_posix())
 tar.add(zipfile,arcname='downloads/'+zipfile.name,filter=perms)
 for client in (root/'artifacts/downloads').glob('edge-vpn-client-*-'+version+'.zip'):
  tar.add(client,arcname='downloads/'+client.name,filter=perms)
report={'archiveSha256':digest(out/('update-'+version+'.tar.gz')),'packageSha256':digest(zipfile),'changed':changed,'size':(out/('update-'+version+'.tar.gz')).stat().st_size}
(out/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
