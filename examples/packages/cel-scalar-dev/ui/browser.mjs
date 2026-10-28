// Real localhost browser proof. Reads private connection/OTP state; emits only
// selected pins/receipts, never cookies, credentials, launch tickets or OTPs.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
const repo=fileURLToPath(new URL("../../../../",import.meta.url));
const require=createRequire(join(repo,"web/workbench/package.json"));
const {chromium}=require("playwright");
const {expect}=require("@playwright/test");
const output=resolve(process.argv[2]||join(repo,"target/package-ui-live"));
const stage=process.argv[3]||"v2";
const reuseConsent=stage==="v2"&&process.argv.includes("--existing-consent");
assert(["v1","v2"].includes(stage));
const state=JSON.parse(await readFile(join(output,"connection.private.json")));
assert.equal(state.stage,stage==="v1"?"v1-preview-adopt":"v2-ready");
const pkg="example.package-reader";
const browser=await chromium.launch();
const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1280,height:1100}});
const page=await context.newPage();
const transcript=[];
const errors=[];
const pageErrors=[];
const computationRequests=[];
page.on("pageerror",error=>{if(pageErrors.length<50)pageErrors.push(String(error.message).slice(0,500));});
page.on("console",message=>{if(message.type()==="error"&&errors.length<50)errors.push(message.text().slice(0,500));});
page.on("request",request=>{if(new URL(request.url()).pathname.endsWith("/tools/call_package_operation"))computationRequests.push({method:request.method()});});
const evidence={stage,origin:state.origin,appPackage:pkg,steps:transcript};
const record=(step,detail={})=>transcript.push({step,...detail});
async function tool(name,args){
  const response=await page.request.post(`${state.origin}/databases/${state.databaseId}/tools/${name}`,{headers:{Origin:state.origin},data:args,timeout:30000});
  const body=await response.json();assert.equal(response.status(),200,JSON.stringify(body));assert.equal(body.error,undefined,JSON.stringify(body));return body;
}
async function signIn(){
  const email=state.users[stage==="v1"?0:1].email;
  await page.goto(`${state.origin}/workbench/`);
  await page.getByLabel("Email address").fill(email);
  await page.getByRole("button",{name:"Email me a code"}).click();
  let code;
  await expect.poll(async()=>{
    const log=await readFile(state.serverLog,"utf8");
    code=[...log.matchAll(/OTP for ([^:\s]+): (\d{6})/g)].filter(m=>m[1]===email).at(-1)?.[2];return code;
  },{timeout:30000}).toMatch(/^\d{6}$/);
  await page.getByLabel("Sign-in code").fill(code);
  const verified=page.waitForResponse(r=>new URL(r.url()).pathname==="/auth/verify-otp"&&r.request().method()==="POST");
  await page.getByRole("button",{name:"Continue",exact:true}).click();
  assert.equal((await verified).status(),200);
  const picker=page.getByRole("region",{name:"Choose a workspace."});
  await expect(picker.or(page.getByRole("button",{name:"New record"})).first()).toBeVisible({timeout:30000});
  if(await picker.isVisible())await picker.getByRole("button",{name:new RegExp(`workspace ${state.databaseId.slice(0,8)}`)}).click();
  await expect(page.getByRole("button",{name:"New record"})).toBeVisible();
  record("ordinary-cookie-sign-in",{member:stage==="v1"?"curator":"fresh member"});
}
try{
  await signIn();
  let listed=await tool("manage_alpha_tabs",{action:"list",view:"full"});
  if(stage==="v2"){
    assert.equal(listed.development_package_operations,"native.package-cel-dev.reads/1");
    evidence.serverDevelopmentContract=listed.development_package_operations;
    const pin=listed.frozen_sources.find(p=>p.package===pkg);
    assert(pin,"verified imported frozen source must be offered to fresh member");
    evidence.sourcePin=pin;
    if(!reuseConsent){
      const install=await tool("manage_alpha_tabs",{action:"install",package:pkg,version:pin.version,digest:pin.digest,artifact_id:pin.artifact_id,source_revision:pin.source_revision,declaration:pin.declaration,reason:"Offer local development package reader to fresh member",idempotency_key:"package-ui-fresh-member"});
      assert.notEqual(install.install.adoption,"shell_adopt.v1");
      record("ordinary-pending-install",{generation:install.install.event_id});
    }
  }
  if(!reuseConsent){
  await page.goto(`${state.origin}/alpha/?workspace=${state.databaseId}&view=${encodeURIComponent(`pending:${pkg}`)}`);
  const previewResponse=page.waitForResponse(r=>r.url().includes("/tools/manage_alpha_tabs")&&r.request().postDataJSON()?.action==="preview");
  await page.getByRole("button",{name:"Preview",exact:true}).click();
  const preview=await previewResponse;assert.equal(preview.status(),200,(await preview.text()).slice(0,1000));
  record("real-shell-preview");
  await expect(page.getByRole("button",{name:"Adopt this version",exact:true})).toBeVisible();
  const adoptedResponse=page.waitForResponse(r=>r.url().includes("/tools/manage_alpha_tabs")&&r.request().postDataJSON()?.action==="adopt");
  await page.getByRole("button",{name:"Adopt this version",exact:true}).click();
  const adopted=await adoptedResponse;assert.equal(adopted.status(),200,(await adopted.text()).slice(0,1000));
  }
  const inspected=await tool("manage_alpha_tabs",{action:"inspect",package:pkg});
  assert.equal(inspected.install.adoption,"shell_adopt.v1");
  const i=inspected.install;
  evidence.install={package:i.package,version:i.version,digest:i.digest,artifact_id:i.artifact_id,source_revision:i.consented_source_revision,declaration_digest:i.declaration_digest,generation:i.event_id,adoption:i.adoption};
  if(reuseConsent){
    const earlier=JSON.parse(await readFile(join(output,"v2-real-consent-evidence.json")));
    assert(earlier.steps.some(step=>step.step==="real-shell-adopt"));
    for(const key of ["generation","digest","source_revision","declaration_digest"])assert.equal(evidence.install[key],earlier.install[key]);
    record("retained-real-shell-consent",{generation:i.event_id});
  }else{
    record("real-shell-adopt",{generation:i.event_id});
    if(stage==="v2")await writeFile(join(output,"v2-real-consent-evidence.json"),JSON.stringify(evidence,null,2)+"\n");
  }
  if(stage==="v1"){
    await page.screenshot({path:join(output,"v1-adopted.png")});
    await writeFile(join(output,"v1-consent-receipt.json"),JSON.stringify(evidence,null,2)+"\n");
    await browser.close();
    await writeFile(join(output,"v1-consented.json"),JSON.stringify({adopted:true,generation:i.event_id})+"\n");
  }else{
    await page.goto(`${state.origin}/alpha/?workspace=${state.databaseId}&view=${encodeURIComponent(`pending:${pkg}`)}`);
    const frame=page.frameLocator(`iframe[title="${pkg} — live tab"]`);
    await expect(frame.getByText("Installed bridge ready. No computation requested.",{exact:true})).toBeVisible({timeout:60000});
    // These reads deliberately are not on APP_EARLY_READS. Observe the real
    // existing gate; never set it from the test or widen the early allowlist.
    await expect.poll(()=>page.evaluate(async()=>{
      const api=await import(new URL("/alpha/lib/api.js",location.href).href);
      return api.bodyAuthorityStamp().writesAuthorized;
    }),{timeout:90000}).toBe(true);
    record("ordinary-workspace-verification-complete");
    const proof=state.packageUI;
    await frame.getByLabel("Record ID").fill(proof.record_id);
    await expect(frame.getByRole("button",{name:"Compute / explicitly retry"})).toBeDisabled();
    const reply=async(name,click)=>{
      const pending=page.waitForResponse(r=>r.url().includes(`/tools/${name}`)&&r.request().method()==="POST");
      await click();const response=await pending;const body=await response.json();return{status:response.status(),body};
    };
    const describe=await reply("describe_package_operations",()=>frame.getByRole("button",{name:"Discover for record"}).click());
    assert.equal(describe.status,200,JSON.stringify(describe.body));
    assert.equal(describe.body.complete,true);
    evidence.description=describe.body;record("ordinary-bridge-record-discovery");
    // Choose a server-returned canonical option. No namespace/package/family
    // identifier is supplied by this driver or inferred from record data.
    const choices=describe.body.packages.flatMap(pkg=>pkg.operations.map(op=>({namespace:pkg.namespace,name:pkg.name,operation:op.name})));
    assert.equal(choices.length,1,"this disposable proof offers one applicable operation");
    await expect(frame.getByRole("button",{name:"Compute / explicitly retry"})).toBeDisabled();
    await frame.getByLabel("Package and operation").selectOption("0");
    evidence.selection=choices[0];record("explicit-server-returned-operation-selection");
    // This proof requires the actual newly built guest host, not the earlier
    // native evaluator. Read one manifest snapshot and compare both successful
    // server receipts with its verified module/source/build identity.
    const hash=bytes=>createHash("sha256").update(bytes).digest("hex");
    const buildBytes=await readFile(join(repo,"target/package-cel-guest/build.json"));
    const build=JSON.parse(buildBytes);
    assert.equal(build.abi,"native.cel-scalar-guest/2");
    assert.deepEqual(build.inventory.imports,[]);
    assert.equal(hash(await readFile(join(repo,"target/package-cel-guest/guest.wasm"))),build.module_sha256);
    const sourceHash=hash(JSON.stringify(build.inputs.map(({path,sha256})=>({path,sha256}))));
    const selected=describe.body.packages.find(p=>p.namespace===choices[0].namespace&&p.name===choices[0].name);
    const operation=selected.operations.find(op=>op.name===choices[0].operation);
    const limits={fuel:50000000,memory_bytes:67108864,table_elements:16384,wasm_call_stack_bytes:1048576,host_worker_stack_bytes:8388608,workers:2,tick_ms:10,deadline_ms:1000,request_bytes:32768,response_bytes:8192,host_compilation_and_native_allocations_guest_bounded:false};
    const expectedGuest={abi:build.abi,module_sha256:build.module_sha256,source_sha256:sourceHash,build_manifest_sha256:hash(buildBytes),runtime:"wasmtime@49.0.1",configuration:"native.cel-guest-dev-host/3",fuel_budget:limits.fuel,deadline_ms:limits.deadline_ms,phase:"Deliver",limits};
    const assertGuestCall=body=>{
      assert.equal(body.result.error,null);
      const receipt=body.receipt,execution=receipt.execution;
      assert.equal(receipt.record_id,proof.record_id);
      assert.equal(receipt.namespace,selected.namespace);assert.equal(receipt.name,selected.name);
      assert.equal(receipt.package_version,selected.version);assert.equal(receipt.package_digest,selected.package_digest);
      assert.equal(receipt.operation,operation.name);
      assert.equal(execution.language,operation.executable.language);assert.equal(execution.profile,operation.executable.profile);
      assert.equal(execution.expression_digest,hash(operation.executable.expression));
      assert.equal(execution.interpreter,"cel-subset@0.14.5/wasmtime-checked-dev/1");
      assert.equal(execution.policy,"cel-subset@1/p1");assert.equal(execution.interim,true);
      const {fuel_used,...guest}=execution.guest;
      assert(Number.isSafeInteger(fuel_used)&&fuel_used>0&&fuel_used<=limits.fuel);
      assert.deepEqual(guest,expectedGuest);
    };
    evidence.expectedGuest=expectedGuest;
    await expect(frame.getByRole("button",{name:"Compute / explicitly retry"})).toBeEnabled();
    const compute=()=>reply("call_package_operation",()=>frame.getByRole("button",{name:"Compute / explicitly retry"}).click());
    const first=await compute();assert.equal(first.status,200,JSON.stringify(first.body));assert.equal(first.body.result.value,900);
    assertGuestCall(first.body);
    await expect(frame.locator("#receipt")).toContainText(proof.record_id);evidence.firstCall=first.body;record("ordinary-bridge-compute");
    await page.screenshot({path:join(output,"v2-computed.png")});
    const cli=join(repo,"target/debug/examples/v2_contract");
    const manifest=join(repo,"examples/packages/cel-scalar-dev/quote.package.json");
    const curate=command=>JSON.parse(execFileSync(cli,["--db",state.dbPath,"--as",proof.curator_binding,command,"--scope",proof.scope_home,"--json",manifest,...(command==="package-adopt"?["--ack-reads",'["record:view"]']:[])],{encoding:"utf8"}));
    curate("package-disable");record("curator-disabled-provider-selection");
    const refused=await compute();assert.notEqual(refused.status,200);evidence.disabledRefusal=refused;record("bridge-call-refused-disabled");
    await expect(frame.locator("#status")).toContainText("Refused:");await page.screenshot({path:join(output,"v2-disabled.png")});
    const read=JSON.parse(execFileSync(cli,["--db",state.dbPath,"--as",proof.curator_binding,"read","--id",proof.record_id],{encoding:"utf8"}));
    const history=JSON.parse(execFileSync(cli,["--db",state.dbPath,"--as",proof.curator_binding,"history","--id",proof.record_id],{encoding:"utf8"}));
    assert(read);assert(history.length>0);evidence.retained={record_id:read.id,historyEvents:history.length};record("retained-record-and-history-readable");
    curate("package-adopt");record("curator-reenabled-selection");
    await expect(frame.getByRole("button",{name:"Compute / explicitly retry"})).toBeEnabled();
    const retried=await compute();assert.equal(retried.status,200,JSON.stringify(retried.body));assert.equal(retried.body.result.value,900);
    assertGuestCall(retried.body);
    assert.notEqual(retried.body.receipt.ack_event_seq,first.body.receipt.ack_event_seq);
    evidence.finalCall=retried.body;record("explicit-user-retry-succeeded");
    await expect(frame.locator("#receipt")).toContainText(String(retried.body.receipt.record_revision));
    await page.screenshot({path:join(output,"v2-retried.png")});
    // Preserve console diagnostics (including existing shell CSP/sign-in
    // notices). Fail uncaught script exceptions separately; HTTP/result and
    // refusal assertions above remain authoritative for this workflow.
    evidence.consoleErrors=errors;
    evidence.pageErrors=pageErrors;
    evidence.computationRequests=computationRequests;
    assert.equal(computationRequests.length,3,"only the three explicit computation clicks dispatch");
    assert.deepEqual(pageErrors,[]);
    await writeFile(join(output,"v2-ui-receipt.json"),JSON.stringify(evidence,null,2)+"\n");
    console.log(JSON.stringify({stage,result:"passed",record_revision:retried.body.receipt.record_revision,receipt:join(output,"v2-ui-receipt.json")}));
  }
}catch(error){
  evidence.hostGate=await page.evaluate(async()=>{
    const api=await import(new URL("/alpha/lib/api.js",location.href).href);
    const gate=api.bodyAuthorityStamp();
    return {writesAuthorized:gate.writesAuthorized,authorityGeneration:gate.authorityGeneration,bootReason:document.documentElement.dataset.bootReason};
  }).catch(()=>null);
  await page.screenshot({path:join(output,`${stage}-failure.png`)}).catch(()=>{});
  await writeFile(join(output,`${stage}-failure.json`),JSON.stringify({evidence,errors,pageErrors,error:String(error.stack)},null,2)+"\n");
  throw error;
}finally{await browser.close();}
