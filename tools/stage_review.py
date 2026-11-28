"""Agent WBQ2 workflow: stage once in an owner-pinned PTY, close, automatically review.
No call to apply-core/apply-return, no approval creation, no retries and no fallback service.
"""
from __future__ import annotations
import argparse, datetime as dt, hmac, json, os, re, zipfile
from pathlib import Path
import wbterm as w, space_budget
HEX=re.compile(r'[0-9a-f]{64}')
def need(ok,why):
    if not ok:raise ValueError(why)
def utc():return dt.datetime.now(dt.timezone.utc).isoformat()
def store(p,info):
    with p.open('x',encoding='utf8') as f:
        json.dump(info,f,indent=2,ensure_ascii=True);f.write('\n');f.flush();os.fsync(f.fileno())
def endpoint_ok(ep):
    return ep==(w.HOST,str(w.PORT),w.USER)
def trust(expected):
    _,saved=w.pin.canonical_saved(w.pin.pin_path(w.HOST,w.PORT),w.HOST,w.PORT)
    need(bool(HEX.fullmatch(expected)) and hmac.compare_digest(expected,saved),'physical host pin does not match saved pairing')
def package(args):
    import r1ctl,wbctl
    # Refuse traversal/reparse data using the same guard as TTY put, before
    # querying a device or creating any issuance marker. Never weaken put.
    a=w.wb_tree.source_path(args.vpk)
    with w.wb_tree.checked_open(a):pass
    sha=args.sha256
    need(HEX.fullmatch(sha) and re.fullmatch(r'\d{2}\.\d{2}-[A-Za-z0-9._-]{1,40}',args.build),'invalid approved release identity')
    # local_package independently constructs the Vita stage and binds the *expected* archive SHA.
    p=r1ctl.local_package(a,sha,args.build);facts=wbctl.vpk_facts(a)
    need(facts['sha256']==sha and facts['title_id']=='INAP00018' and p['version']==facts['app_ver'],'package changed')
    with zipfile.ZipFile(a) as z:
        p['members']=[f'member {i.filename} size={i.file_size} crc={i.CRC:08X}' for i in z.infolist()]
        p['expanded']=sum(i.file_size for i in z.infolist())
    p.update(size=facts['bytes'],required=space_budget.requirement(facts)['required'])
    return p
def reply(t,cmd):
    t.command(cmd);out=[];size=0
    rp=getattr(t,'root_prompt',w.ROOT_PROMPT)
    for _ in range(32):
        while not t.buf:t._more()
        while len(t.buf)<len(rp) and rp.startswith(t.buf):t._more()
        if t.buf.startswith(rp):
            t.exact(rp);return [x for x in out if x]
        line=t.line().decode('ascii');size+=len(line)
        need(size<=12288 and all(32<=ord(c)<127 or c=='\t' for c in line),'malformed terminal reply')
        out.append(line)
    raise ValueError('too many reply lines')
def grant_idle(out,source,prior):
    import r1ctl
    if len(out)!=1:return False
    st=r1ctl.parse_state(out[0])
    if st['state']=='none':
        return st==dict(state='none',run=source['run'],source_run='-',nonce='-',target='-',manifest='-')
    if st['state']!='returned' or prior is None:return False
    j=json.loads(prior.read_bytes());ident=j['returned_identity']
    return (st==j['technical_proof'] and j['pending']=='pending-core: no' and st['run']==ident['run']==source['run'] and
            st['target']==ident['version']==source['version'] and ident['build']==source['build'] and
            ident['host_pin']==source['host_sha256'] and j.get('result')=='VERIFIED_'+source['version']+'_AND_MATCHING_R1_PROOF')
def enough_power(data):
    vals={}
    for k in ('battery','temp_c','online'):
        v=[int(m[1]) for row in data if (m:=re.fullmatch('payload '+k+r'=(\d+)',row))]
        if len(v)!=1:return False
        vals[k]=v[0]
    return vals['online']==1 and 25<=vals['battery']<=100 and 0<=vals['temp_c']<=40
def stage(a,p,d,log):
    remote='ux0:/VITA-POC/workbench_'+p['version'].replace('.','')+'-'+a.sha256[:12]+'.vpk'
    q=w.quoted_path(remote)
    with w.paired_terminal() as t:
        t.ch.settimeout(45);s=t.check()
        need(s['channel']=='one interactive PTY' and hmac.compare_digest(s['host_sha256'],a.host_pin) and re.fullmatch(r'[0-9A-F]{16}',s['run']),'unexpected session')
        v=s['version'];need(re.fullmatch(r'\d{2}\.\d{2}',v) and '01.80'<=v<p['version'],'source too old or candidate not newer')
        def cmd(c):
            out=reply(t,c);log.append(dict(command=c,output=out));return out
        def guard():
            need(cmd('pending')==['pending-core: no'] and grant_idle(cmd('r1-status'),s,a.prior_return),'occupied queue or unrelated grant')
            need(cmd('updater check')==['OK updater-check title=INAP00019 helper=reuse epoch=01.73 promote=0'],'updater reuse not verified')
            need(enough_power(cmd('ext sys')),'AC/battery check failed')
            req=p['required'];out=cmd('df '+str(req));m=re.fullmatch(r'df volume=ux0: total=(\d+) available=(\d+) required=(\d+)',out[0] if len(out)==1 else '')
            need(m and req==int(m[3])<=int(m[2])<=int(m[1])<=space_budget.LIMIT,'space check failed')
        guard();need(cmd('tree-stat '+q)==['TTY1 OK ABSENT'],'destination exists or unreadable; do not overwrite')
        store(d/'upload-issued.json',dict(utc=utc(),source=s,remote=remote,sha256=a.sha256))
        upload=t.push(a.vpk,remote);need(upload==dict(action='put',remote=remote,bytes=p['size'],sha256=a.sha256),'upload unconfirmed')
        need(sorted(cmd('inspect '+q))==sorted([f"file bytes={p['size']} sha256={a.sha256}",*p['members'],f"title_id=INAP00018 app_ver={p['version']} title=Vita Agent Workbench"]),'unexpected inspected stage file')
        plan=[f"plan file bytes={p['size']} sha256={a.sha256}",f"plan title=INAP00018 app_ver={p['version']} running={v} installed={v} title_ok=1",'plan verdict=newer core=replace payload=replace queue=yes force=no',*['plan '+x for x in p['members']]]
        need(sorted(cmd('plan '+q))==sorted(plan),'device plan mismatch')
        guard();trust(a.host_pin);need(t.check()==s,'source changed')
        store(d/'stage-issued.json',dict(utc=utc(),source=s,remote=remote,receipt=p['receipt']))
        ack=cmd('install '+q+' sha256='+a.sha256+' --no-reload')
        fmt='OK install version='+re.escape(p['version'])+rf" title=INAP00018 files=3 bytes={p['expanded']} payload=(?:none|01\.22-p2\.1) core=queued session=kept"
        need(not any(x.startswith(('ERR','WARN')) for x in ack) and sum(bool(re.fullmatch(fmt,x)) for x in ack)==1,'stage ACK unconfirmed; do not retry')
        need(cmd('pending')==['pending-core: '+p['receipt']],'staged receipt differs; do not retry')
        need(grant_idle(cmd('r1-status'),s,None) and t.check()==s,'source or grant changed after staging')
        result=dict(utc=utc(),source=s,remote=remote,package=p,upload=upload,pending=p['receipt'],idle_source_run=s['run'],result='STAGED_NOT_APPLIED')
        store(d/'stage-confirmed.json',result)
    return result
def automatic_review(a,d):
    import review_digest as reviewer
    def query(expected):
        return reviewer.verify(expected,notice_issue=lambda intent:store(d/'notice-issued.json',dict(utc=utc(),**intent)))
    def load(vpk,approved,record):
        return reviewer.load_expected(w.wb_tree.source_path(vpk),approved,record)
    options=argparse.Namespace(vpk=a.vpk,sha256=a.sha256,stage=d/'stage-confirmed.json')
    return reviewer.execute(options,(w.HOST,str(w.PORT),w.USER),loader=load,query=query)
def workflow(a,ep,*,get_package=package,check_pin=trust,do_stage=stage,review=automatic_review):
    need(endpoint_ok(ep),'wrong endpoint'); check_pin(a.host_pin); p=get_package(a)
    if not a.stage:return 0,dict(status='LOCAL_PREVIEW_ONLY',package=p,queued=False)
    d=a.records.resolve();d.mkdir(parents=True,exist_ok=False) # refusal on reuse covers an indeterminate earlier submission
    log=[];result={'status':'UNCONFIRMED','do_not_restage':True};rc=3
    try:
        s=do_stage(a,p,d,log);need(s['result']=='STAGED_NOT_APPLIED','incomplete staging record')
        result=dict(status='QUEUED_REVIEW_UNCONFIRMED',queued=True,do_not_restage=True)
        code,j=review(a,d);store(d/'digest-review.json',j)
        need(code==0 and j.get('status')=='MATCH' and j.get('groups_matched')==8 and j.get('approval')=='LOCAL_OWNER_REQUIRED','digest review not matched')
        expect_groups=[p['manifest'][i:i+8].upper() for i in range(0,64,8)]
        need(j.get('groups')==expect_groups and j.get('manifest_sha256')==p['manifest'] and j.get('title')=='INAP00018' and
             j.get('target')==p['version'] and j.get('vpk_sha256')==a.sha256 and j.get('wbq2_bytes')==int(p['receipt'].split()[3]) and
             j.get('host_sha256')==a.host_pin and j.get('source_run')==s['source']['run'] and
             j.get('source_version')==s['source']['version'] and j.get('applied') is False and j.get('authorized_by_agent') is False,
             'review not bound to this undecided queue/package')
        level=j.get('evidence');need(level==('PAIRED_PENDING_ONLY' if s['source']['version']=='01.80' else 'LOCAL_REVIEW_MODEL'),'unexpected review evidence level')
        r=dict(status='QUEUED_AND_REVIEWED',queued=True,title=j['title'],target=j['target'],groups_matched=8,evidence=level,
               approval='LOCAL_OWNER_REQUIRED',authorized_by_agent=False,applied=False,review=str(d/'digest-review.json'))
        if s['source']['version']<'01.82':
            result=dict(**r,owner_action='TRIANGLE_THEN_CROSS',notice_status='LEGACY_SOURCE');rc=0
        else:
            notice=j.get('notice',{})
            if (notice.get('status')=='ACKNOWLEDGED' and notice.get('title')==j['title'] and notice.get('target')==j['target'] and
                notice.get('bytes')==j['wbq2_bytes'] and notice.get('source_run')==j['source_run'] and
                notice.get('source_version')==j['source_version'] and notice.get('manifest')==j['manifest_sha256'] and
                notice.get('host_sha256')==j['host_sha256'] and notice.get('transport_sha256')==j.get('transport_sha256')):
                result=dict(**r,owner_action='CROSS_WHEN_APPROVAL_PROMPT_VISIBLE',notice_status='ACKNOWLEDGED',
                            notice_screen_verified=False);rc=0
            else:
                result=dict(r,status='QUEUED_AND_REVIEWED_NOTICE_UNCONFIRMED',owner_action='WAIT_FOR_CONFIRMATION',
                            notice_status=notice.get('status','UNCONFIRMED'),do_not_resend_notice=True,do_not_restage=True)
    except Exception as exc:
        result['error']=type(exc).__name__+': '+str(exc)[:200]
    finally:
        store(d/'workflow.json',dict(utc=utc(),result=result,stage_observations=log))
    return rc,result
def register(sub):
    p=sub.add_parser('stage-review',allow_abbrev=False,help='stage once, compare digest, show receipt when supported; never apply')
    for k in ('vpk','records'):p.add_argument('--'+k,type=Path,required=True)
    for k in ('sha256','build','host-pin'):p.add_argument('--'+k,required=True)
    p.add_argument('--prior-return',type=Path,help='existing verified return receipt, if current R1 still reports returned')
    p.add_argument('--stage',action='store_true',help='explicitly perform staging; otherwise only check the local candidate')
    p.add_argument('--json',action='store_true',default=argparse.SUPPRESS)
def command(a,ep):
    try:rc,j=workflow(a,ep)
    except Exception as exc:rc,j=3,dict(status='NOT_STARTED',reason=type(exc).__name__+': '+str(exc)[:200])
    print(json.dumps(j,ensure_ascii=True,indent=None if a.json else 2));return rc
