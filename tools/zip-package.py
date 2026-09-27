import sys,zipfile
from pathlib import Path
source,target=Path(sys.argv[1]),Path(sys.argv[2]);client='--client' in sys.argv[3:]
with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for file in source.rglob('*'):
  if not file.is_file():continue
  rel=file.relative_to(source)
  if file.name=='client.json' or file.suffix in ('.pdb','.dbg','.env') or 'data' in rel.parts:continue
  if client and len(rel.parts)>1:continue
  if file.suffix == ".sh": z.writestr(rel.as_posix(),file.read_text(encoding="utf-8-sig").replace("\r\n","\n"))
  else: z.write(file,rel.as_posix())
