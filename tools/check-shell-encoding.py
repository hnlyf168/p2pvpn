from pathlib import Path
import zipfile
for f in ['src/Client/install-linux.sh','src/Client/uninstall-linux.sh','src/ControlPlane/Installers/install.sh','src/Client/安装客户端.cmd']:
 b=Path(f).read_bytes();print(f,'BOM=',b.startswith(bytes.fromhex('efbbbf')),'CRLF=',b.count(b'\r\n'),'LF=',b.count(b'\n'))
with zipfile.ZipFile('artifacts/downloads/edge-vpn-client-linux-x64-0.3.0.zip') as z:
 b=z.read('install-linux.sh');print('PACKAGED LINUX SCRIPT: BOM=',b.startswith(bytes.fromhex('efbbbf')),'CRLF=',b.count(b'\r\n'))
