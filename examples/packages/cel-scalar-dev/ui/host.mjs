// Local synthetic proof only. Uses prebuilt binaries; never compiles, deploys,
// edits an authority projection, or supplies an app assertion for the browser.
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile, rename } from "node:fs/promises";
import { createWriteStream } from "node:fs";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import https from "node:https";
import http from "node:http";
import net from "node:net";
const repo = fileURLToPath(new URL("../../../../", import.meta.url));
const port = Number(process.env.PACKAGE_UI_PORT || "4495");
if (!Number.isSafeInteger(port) || port < 1024 || port > 65534) throw new Error("invalid local port");
for (const candidate of [port,port+1]) await new Promise((ok,fail)=>{
  const probe=net.createServer();probe.once("error",fail);
  probe.listen(candidate,"127.0.0.1",()=>probe.close(ok));
});
const origin = `https://localhost:${port}`;
const output = resolve(process.argv[2] || join(repo, "target/package-ui-live"));
await mkdir(output, {recursive:true, mode:0o700});
const resume=process.argv[3]==="--resume";
const previous=resume?JSON.parse(await readFile(join(output,"connection.private.json"))):null;
const root = resume?previous.root:await mkdtemp("/tmp/native-v2-browser-package-ui-");
const fixture = join(root,"fixture");
if(resume){
  if(!root.startsWith("/tmp/native-v2-browser-package-ui-")||previous.fixture!==fixture||previous.stage!=="v2-ready")throw new Error("resume requires this proof's retained ready fixture");
}else await mkdir(fixture);
const children = new Set();
function start(bin,args,extra={}) {
  const child=spawn(bin,args,{cwd:repo,env:process.env,stdio:["ignore","pipe","pipe"],detached:true,...extra});
  children.add(child); child.once("exit",()=>children.delete(child));
  return child;
}
async function done(child) {
  const code=await new Promise((ok,fail)=>{child.once("error",fail);child.once("exit",ok);});
  if(code!==0) throw new Error(`owned proof process exited ${code}`);
}
async function stop(child) {
  if(child.exitCode!==null || child.signalCode!==null)return;
  const ended=new Promise(ok=>child.once("exit",ok));
  process.kill(-child.pid,"SIGTERM");
  const kill=setTimeout(()=>{try{process.kill(-child.pid,"SIGKILL");}catch{}},8000);
  await ended;clearTimeout(kill);
}
async function waitFile(path,ms=900000) {
  const end=Date.now()+ms;
  while(Date.now()<end){try{return JSON.parse(await readFile(path,"utf8"));}catch(error){if(error.code!=="ENOENT")throw error;}await new Promise(ok=>setTimeout(ok,250));}
  throw new Error(`timed out waiting for ${path}`);
}
const state={...previous,origin,root,fixture,output,port,pid:process.pid,stage:"preparing"};
const stateFile=join(output,"connection.private.json");
async function publish(stage,details={}) {
  Object.assign(state,details,{stage});
  await writeFile(stateFile+".tmp",JSON.stringify(state,null,2)+"\n",{mode:0o600});
  await rename(stateFile+".tmp",stateFile);
  console.log(JSON.stringify({stage,connection:stateFile}));
}
await publish("preparing");
const key=join(root,"key.pem"),cert=join(root,"cert.pem");
await done(start("openssl",["req","-x509","-newkey","rsa:2048","-sha256","-nodes","-days","1","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost,DNS:artifact.localhost","-keyout",key,"-out",cert]));
const proxy=https.createServer({key:await readFile(key),cert:await readFile(cert)},(req,res)=>{
  const upstream=http.request({hostname:"127.0.0.1",port:port+1,path:req.url,method:req.method,headers:req.headers},reply=>{res.writeHead(reply.statusCode,reply.headers);reply.pipe(res);});
  upstream.on("error",()=>{if(!res.headersSent)res.writeHead(502);res.end();});
  req.on("aborted",()=>upstream.destroy());req.pipe(upstream);
});
proxy.on("upgrade",(req,socket,head)=>{
  const upstream=net.connect(port+1,"127.0.0.1",()=>{
    upstream.write(`${req.method} ${req.url} HTTP/${req.httpVersion}\r\n${Object.entries(req.headers).map(([k,v])=>`${k}: ${v}`).join("\r\n")}\r\n\r\n`);
    if(head.length)upstream.write(head);socket.pipe(upstream).pipe(socket);
  });
  upstream.on("error",()=>socket.destroy());socket.on("error",()=>upstream.destroy());socket.on("close",()=>upstream.destroy());
});
await new Promise((ok,fail)=>{proxy.once("error",fail);proxy.listen(port,"127.0.0.1",ok);});
async function serve(stage) {
  const logPath=join(output,`${stage}-server.private.log`);
  const log=createWriteStream(logPath,{mode:0o600});
  const child=start(join(repo,"target/debug/serve"),[],{env:{...process.env,
    RUST_MIN_STACK:"67108864",
    NATIVE_CE_BIND:`127.0.0.1:${port+1}`,NATIVE_CE_PUBLIC_ORIGIN:origin,NATIVE_CE_ARTIFACT_ORIGIN:`https://artifact.localhost:${port}`,
    NATIVE_FEDERATION_NETWORK_ID:"dns:localhost.test",NATIVE_FEDERATION_INSTALLATION_ID:"00000000-0000-4000-8000-000000000005",
    NATIVE_FEDERATION_CUSTODY_KEY:Buffer.alloc(32,42).toString("base64url"),NATIVE_FEDERATION_CUSTODY_DIR:join(fixture,"data/federation-custody/self-hosted"),
    NATIVE_CE_FRESH_ADOPTION_CUSTODY:"false",NATIVE_CE_EFFECT_GESTURE_ENFORCEMENT:"true",NATIVE_CE_APP_BUNDLE_URLS:"true",
    NATIVE_CE_APP_BUNDLE_KEYRING:JSON.stringify({active_key_id:"browser-1",keys:[{id:"browser-1",key:Buffer.alloc(32,43).toString("base64")}]}),
    NATIVE_CE_DATA_DIR:join(fixture,"data"),NATIVE_CE_BACKUP:"off",NATIVE_CE_SHUTDOWN_TIMEOUT_SECS:"3",
    NATIVE_CE_MCP_PLAN_KEYRING:JSON.stringify({active_key_id:"test-1",keys:[{id:"test-1",key:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}),
  }});
  child.stdout.pipe(log);child.stderr.pipe(log);
  for(let tries=0;tries<120;tries++){
    if(child.exitCode!==null)throw new Error("local host stopped; inspect private log");
    try{if((await fetch(`http://127.0.0.1:${port+1}/health`)).ok)return{child,logPath};}catch{}
    await new Promise(ok=>setTimeout(ok,500));
  }
  throw new Error("local host readiness timed out");
}
for(const signal of ["SIGINT","SIGTERM"])process.once(signal,async()=>{await Promise.all([...children].map(stop));proxy.close();process.exit(0);});
try {
  if(resume){
    await done(start(join(repo,"target/debug/examples/v2-browser-fixture"),[fixture,"--verify"]));
  }else{
  const fixtureLog=createWriteStream(join(output,"fixture.private.log"),{mode:0o600});
  const child=start(join(repo,"target/debug/examples/v2-browser-fixture"),[fixture],{env:{...process.env,NATIVE_CE_V2_BROWSER_PORT:String(port),NATIVE_CE_V2_BROWSER_RECORDS:"12",NATIVE_CE_PACKAGE_UI_PROOF:"1",NATIVE_CE_FROZEN_BUNDLES_DIR:join(repo,"target/package-ui-bundle")}});
  child.stdout.pipe(fixtureLog);child.stderr.pipe(fixtureLog);
  const fixtureDone=done(child);fixtureDone.catch(()=>{});
  const pending=await Promise.race([waitFile(join(fixture,"pending-package-ui.json")),fixtureDone.then(()=>{throw new Error("fixture ended before the consent pause");})]);
  const v1=await serve("v1");await publish("v1-preview-adopt",{...pending,serverLog:v1.logPath});
  await waitFile(join(output,"v1-consented.json"));
  await stop(v1.child);
  await writeFile(join(fixture,"continue-after-browser-consent"),"{}\n");
  await fixtureDone;
  }
  const ready=JSON.parse(await readFile(join(fixture,"fixture.json"),"utf8"));
  const v2=await serve("v2");
  await publish("v2-ready",{...ready,serverLog:v2.logPath,dbPath:join(fixture,"data/databases",`${ready.databaseId}.db`)});
  // Remain alive for the separately commissioned fresh consumer. Parent owns
  // release/cleanup; this process never automatically destroys proof state.
  await new Promise((_,fail)=>v2.child.once("exit",code=>fail(new Error(`retained host exited ${code}`))));
} catch(error) {
  console.error(error);await Promise.all([...children].map(stop));proxy.close();process.exitCode=1;
}
