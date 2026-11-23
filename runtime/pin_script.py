import hashlib,pathlib,sys
p=pathlib.Path(sys.argv[1]); data=p.read_bytes()
if hashlib.sha256(data).hexdigest()!='ec216ac6378407a863cdc52fd3bac41e6060fed4341a8436a06e16004f6a191d':raise SystemExit('refusing unapproved script')
out=pathlib.Path(sys.argv[2]);out.write_text(''.join(','.join(str(x) for x in data[i:i+32])+',\n' for i in range(0,len(data),32)))
