"""Trust only a local project snapshot. Extract named source files, never execute code or scripts from the zip itself."""
from pathlib import Path
import sys,zipfile,tempfile,subprocess
H=Path(__file__).resolve().parent
def main():
 src=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else H.parents[1]/'source'
 with tempfile.TemporaryDirectory() as td:
  w=Path(td)
  if src.is_file():
   with zipfile.ZipFile(src) as z:
    for i in z.infolist():
     n=Path(i.filename)
     if n.parent.as_posix()=='source' and n.suffix in ('.h','.c','.inc') and n.name.isascii() and all(c.isalnum() or c in '._-' for c in n.name):
      (w/n.name).write_bytes(z.read(i))
   src=w
  argv=['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(src),str(H/'probe.c'),*[str(src/(k+'.c')) for k in ('wb_shell','wb_cmd','wb_out','wb_str')],'-o',str(w/'p.exe')]
  subprocess.run(argv,check=True,timeout=60)
  sys.stdout.buffer.write(subprocess.check_output([str(w/'p.exe')],timeout=15))
if __name__=='__main__':main()
