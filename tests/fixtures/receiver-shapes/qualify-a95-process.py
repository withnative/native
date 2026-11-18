#!/usr/bin/env python3
import json,hashlib,shutil,subprocess,os,argparse
from pathlib import Path
from datetime import datetime,timezone
parser=argparse.ArgumentParser(description='Qualify a stamped receiver serving95 with honest age and write refusal, only on a copied private fixture.')
parser.add_argument('--fixture',required=True,type=Path)
parser.add_argument('--destination',required=True,type=Path)
parser.add_argument('--binary',required=True,type=Path)
parser.add_argument('--source',required=True)
parser.add_argument('--receipt',required=True,type=Path)
args=parser.parse_args()
source=args.fixture.resolve(strict=True);dest=args.destination.resolve()
assert source.is_relative_to('/tmp') and dest.is_relative_to('/tmp')
assert json.loads((source/'expected.json').read_text())['record_id']=='70110000-0000-4000-8000-000000000095'
assert Path(json.loads((source/'standby.json').read_text())['replica_root']).resolve()==source/'replica'
assert not dest.exists();shutil.copytree(source,dest,copy_function=shutil.copy2)
expected=json.loads((dest/'expected.json').read_text());cfg=json.loads((dest/'standby.json').read_text());cfg['replica_root']=str(dest/'replica');(dest/'standby.json').write_text(json.dumps(cfg))
root=dest/'replica/accepted';pointer=json.loads((root/'current.json').read_text());pointer['generation_id']=expected['new_generation'];pointer['snapshot_sha256']=expected['new_snapshot_sha256'];(root/'current.json').write_text(json.dumps(pointer))
paths={name:root/'generations'/expected[name+'_generation']/'snapshot.db' for name in ['old','new']}
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
original={k:digest(p) for k,p in paths.items()};pin=(root/'shape-rollback-pins.json').read_bytes()
binary=args.binary.resolve(strict=True);identity=json.loads(subprocess.check_output([str(binary),'--standby-identity']))
assert identity['source_sha']==args.source
assert identity['artifact_sha256']==digest(binary)
calls=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2026-07-28','capabilities':{},'clientInfo':{'name':'receiver95-process-proof','version':'1'}}},{'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'records_read','arguments':{'operation':'get_record','arguments':{'ids':[expected['record_id']]},'format':'json'}}},{'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'records_write','arguments':{'operation':'update_record','arguments':{'id':expected['record_id'],'body_append':' must never reach local copy','reason':'Private read-only receiver proof','idempotency_key':'receiver-no-local-write'},'format':'json'}}}]
result=subprocess.run([str(binary),'--standby',str(dest/'standby.json')],input=''.join(json.dumps(c)+'\n' for c in calls),env={'PATH':'/usr/bin:/bin','RUST_MIN_STACK':'67108864','NATIVE_CE_MCP_SURFACE':'executor'},capture_output=True,text=True,timeout=60)
assert result.returncode==0,result.stderr
replies={r['id']:r for r in map(json.loads,result.stdout.splitlines()) if 'id' in r}
value=replies[2]['result']['structuredContent'];assert not replies[2]['result'].get('isError'),replies[2]
assert value['records'][0]['body']=='Verified94 remains readable',value
context=value['standby_context'];assert context['mode']=='standby' and context['serving_generation_id']==expected['new_generation'],context
manifest=json.loads((paths['new'].parent/'manifest.json').read_text());capture=datetime.fromisoformat(manifest['captured_at'].replace('Z','+00:00'));age=max(0,int((datetime.now(timezone.utc)-capture).total_seconds()));assert abs(age-context['freshness']['age_seconds'])<=5,context
assert replies[3]['result'].get('isError') and replies[3]['result']['structuredContent']['error_code']=='STANDBY_READ_ONLY',replies[3]
assert {k:digest(p) for k,p in paths.items()}==original
assert (root/'shape-rollback-pins.json').read_bytes()==pin
receipt={'result':'stamped A serves95 with actual95 capture age; write refused; both snapshots and pin unchanged','identity':identity,'expected':expected,'read':replies[2],'write_refusal':replies[3],'diagnostics':result.stderr.splitlines()}
out=args.receipt;out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'result':receipt['result'],'receipt':str(out),'age_seconds':context['freshness']['age_seconds']}))
