from pathlib import Path
import subprocess,shutil,sys
script=Path(sys.argv[1] if len(sys.argv)>1 else 'src/ControlPlane/Installers/install.sh').read_text(encoding='utf-8')
block=script.split('# BEGIN STORAGE CHECK\n')[1].split('# END STORAGE CHECK')[0]
shell=shutil.which('sh')
assert shell,'Run this POSIX shell test on Linux'
def run(free=512000,inodes='1000',split=False,readonly=False):
 prefix='set -eu\nfail() { echo "$*" >&2; exit 1; }; stage=/tmp/edge-vpn-test; mode=install;\n'
 prefix+='stat() { '+('printf "%s" "$3"' if split else "echo 1")+'; };\n'
 prefix+="df() { printf 'Filesystem total used available use mount\\n'; case \"$1\" in -Pk) echo 'fs 1000000 100 "+str(free)+" 0% /';; *) echo 'fs 10000 100 "+str(inodes)+" 0% /';; esac; };\n"
 r=subprocess.run([shell,'-c',prefix+(block.replace('[ -w "$parent" ]','false') if readonly else block)],capture_output=True,text=True)
 return r.returncode,r.stdout+r.stderr
assert run()[0]==0
assert run(free=0)[0]!=0
assert 'inodes' in run(inodes=0)[1]
assert run(inodes='-')[0]==0
assert run(free=102400)[0]!=0
assert run(free=102400,split=True)[0]==0
assert 'read-only' in run(readonly=True)[1]
assert script.index('# BEGIN STORAGE CHECK')<script.index('mkdir -p "$stage"')<script.index('$control/api/install/redeem')
assert 'python' not in script and 'jq ' not in script and 'eval ' not in script
print('PASS: shell storage checks, full disk, inode exhaustion, unknown inode capacity, read-only, shared/separate filesystem budgets; no Python/jq/eval dependency.')
# A competing installer must not remove the active installer request/claim files.
import tempfile
with tempfile.TemporaryDirectory() as temp:
 stage=Path(temp);(stage/'client').mkdir();(stage/'claim.txt.tmp').write_text('keep');(stage/'redeem.request').write_text('keep')
 cleanup=script.split('cleanup() {')[1].split('\ntrap cleanup')[0]
 command='stage="'+temp+'"; transient=; lock=; cleanup() {'+cleanup+'\ncleanup'
 subprocess.run([shell,'-c',command],check=True)
 assert (stage/'claim.txt.tmp').exists() and (stage/'redeem.request').exists()
print('PASS: failed lock acquisition cannot remove another installer temporary credentials.')
