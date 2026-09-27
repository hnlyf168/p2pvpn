from pathlib import Path
from unittest.mock import patch
import subprocess,shutil,struct,zipfile,sys
script=Path(sys.argv[1] if len(sys.argv)>1 else 'src/ControlPlane/Installers/install.sh').read_text(encoding='utf-8')
block=script.split('elf=/proc/$$/exe')[1].split("printf 'Detected client platform:")[0]
block='elf=/proc/$$/exe'+block
shell=shutil.which('sh') or str(Path(shutil.which('git')).parent.parent/'bin/sh.exe')
for machine,elfclass,expected in [('x86_64',2,'linux-x64'),('aarch64',2,'linux-arm64'),('arm64',2,'linux-arm64'),('armv7l',1,'linux-arm'),('aarch64',1,'linux-arm'),('i686',1,None),('x86_64',1,None),('armv6l',1,None),('mips',2,None)]:
 prefix="fail() { exit 1; }; uname() { printf '%s' '"+machine+"'; }; od() { printf '%s' '"+str(elfclass)+"'; };\n"
 r=subprocess.run([shell,'-c',prefix+block+'\nprintf "%s" "$platform"'],capture_output=True,text=True)
 assert (r.stdout if r.returncode==0 else None)==expected,(machine,elfclass,r.stdout,r.stderr)
print('PASS: actual shell architecture selection, including 32-bit ARM userspace on a 64-bit kernel; x86/ARMv6 rejected.')
for rid,elfclass,machine in [('linux-arm',1,40),('linux-arm64',2,183),('linux-x64',2,62)]:
 package=Path('artifacts/downloads')/('edge-vpn-client-'+rid+'-0.3.3.zip')
 if not package.exists():continue
 with zipfile.ZipFile(package) as z:
  executable=z.read('P2PVpnClient');assert executable[:4]==b'\x7fELF';assert executable[4]==elfclass;assert struct.unpack_from('<H',executable,18)[0]==machine
  assert 'client.json' not in z.namelist()
  for name in ['install-linux.sh','uninstall-linux.sh']:
   data=z.read(name);assert b'\r' not in data and not data.startswith(b'\xef\xbb\xbf')
 print('PASS: '+rid+' archive architecture, clean scripts, no enrolled credentials.')
