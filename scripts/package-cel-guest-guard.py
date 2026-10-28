import os,sys,subprocess,time,signal,shutil,json,pathlib,datetime
root=pathlib.Path(__file__).resolve().parents[1]
label=sys.argv[1];cmd=sys.argv[2:];out=root/'target/package-cel-guest-stage3'
out.mkdir(parents=True,exist_ok=True)
env=os.environ.copy();env.update(CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(root/'target'),RUSTC_WRAPPER='')
start=shutil.disk_usage(root).free
if start<12*1024**3: raise SystemExit('refuse: below 12GiB disk guard')
receipt={'command':cmd,'cwd':str(root),'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'initial_free_bytes':start,'minimum_free_bytes':start,'target_dir':env['CARGO_TARGET_DIR'],'CARGO_INCREMENTAL':'0','jobs':2,'environment':{k:env[k] for k in ['CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS','PACKAGE_CEL_GUEST_WASM','RUST_MIN_STACK'] if k in env}}
with (out/(label+'.log')).open('w') as log:
 p=subprocess.Popen(cmd,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 receipt['owned_pgid']=p.pid
 try:
  while p.poll() is None:
   free=shutil.disk_usage(root).free;receipt['minimum_free_bytes']=min(free,receipt['minimum_free_bytes'])
   if free<12*1024**3:
    receipt['guard_stop']='actual free space below12GiB';os.killpg(p.pid,signal.SIGTERM)
    try:p.wait(timeout=10)
    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
    break
   time.sleep(1)
 except BaseException:
  if p.poll() is None:os.killpg(p.pid,signal.SIGTERM);p.wait()
  raise
 receipt['exit_code']=p.returncode
 receipt['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 (out/(label+'.json')).write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt));sys.exit(p.returncode if p.returncode>=0 else 128-p.returncode)
