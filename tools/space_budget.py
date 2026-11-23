"""Fail-closed 5090 preflight. Byte budget is conservative, not a reservation."""
import re
DEFAULT_RESERVE=4*1024*1024    # updater, head.bin, directory/allocation overhead
LIMIT=(1<<64)-1
def requirement(facts,extra=0):
    upload=facts['bytes']
    sizes=[m['size'] for m in facts['members']]
    if not isinstance(extra,int) or extra<0 or upload<=0 or any(n<0 for n in sizes):
        raise ValueError('invalid space input')
    # Incoming plus verification copy; both public/private full expanded stages and payload rotation.
    stage=sum(sizes)
    payload=sum(m['size'] for m in facts['members'] if m['name']=='workbench_payload.suprx')
    budget=2*upload+2*stage+2*payload+DEFAULT_RESERVE+extra
    if budget>LIMIT:raise ValueError('space budget overflows uint64')
    return dict(required=budget,upload=upload,expanded_stage=stage,private_final_stage=stage,payload_copies=2*payload,
                updater_and_overhead=DEFAULT_RESERVE,extra_reserve=extra)
def probe(ssh,required):
    rc,out=ssh('df '+str(required))
    m=re.fullmatch(r'df volume=ux0: total=(\d+) available=(\d+) required=(\d+)',out)
    if rc==0 and m:
        total,avail,req=map(int,m.groups())
        if 0<total<=LIMIT and required==req and required<=avail<=total:
            return dict(ok=True,state='sufficient',total=total,available=avail,required=req)
    m=re.fullmatch(r'ERR no-space volume=ux0: required=(\d+) available=(\d+) total=(\d+)(?:\nERR [^\n]+)?',out)
    if rc==1 and m:
        req,avail,total=map(int,m.groups())
        if 0<total<=LIMIT and req==required and avail<req and avail<=total:
            return dict(ok=False,state='insufficient',total=total,available=avail,required=req)
    return dict(ok=False,state='unavailable',required=required,rc=rc,detail=out)
def display(report):
    return 'ux0: '+report['state']+' required='+str(report['required'])+' available='+str(report.get('available','?'))+' total='+str(report.get('total','?'))
