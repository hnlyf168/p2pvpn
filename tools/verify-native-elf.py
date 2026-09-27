from pathlib import Path
import struct,json,sys
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
if __name__ == '__main__':
 report=inspect_elf(Path(sys.argv[1]).read_bytes())
 if len(sys.argv)>2:
  expected={'linux-x64':62,'linux-arm64':183,'linux-arm':40}[sys.argv[2]]
  assert report['machine']==expected, 'Architecture mismatch'
 print(json.dumps(report))
