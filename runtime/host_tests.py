"""Run deterministic assertions on the real MicroPython VM, using a Linux test stdin/stdout."""
import pathlib,subprocess,sys
exe=str(pathlib.Path(sys.argv[1]).resolve()); dst=pathlib.Path('game-host-proof'); dst.mkdir(exist_ok=True)
cases=[
 ('pvp','5\n1\n4\n2\n5\n3\nq\n6\n',0,('X wins!','Player X wins 1 games','♥','Goodbye and save the world!'),8800),
 ('ai','invalid\n4\n8\nq\n6\n',0,('Invalid choice.',"O's turn.",'X makes a move','Goodbye and save the world!'),7500),
 ('eof','',2,('Enter choice: ',),0),('takeover-input',"__import__('os')\n6\n",0,('Invalid choice.','Goodbye and save the world!'),6000)]
for name,inputs,rc,required,delay in cases:
 p=subprocess.run([exe],input=inputs.encode(),capture_output=True,timeout=30)
 (dst/(name+'.stdin')).write_bytes(inputs.encode());(dst/(name+'.stdout')).write_bytes(p.stdout);(dst/(name+'.stderr')).write_bytes(p.stderr)
 out=p.stdout.decode();err=p.stderr.decode();assert p.returncode==rc and all(x in out for x in required) and ('requested_delay_ms='+str(delay)+' ') in err and ('rc='+('-2' if name=='eof' else '0')+';') in err,(name,p.returncode,out[-450:],err)
 print('PASS',name,'exit',p.returncode,'virtual delay_ms',delay)
