// Fixed immutable-main/root source oracles; no expected values from this implementation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { planInstall, runInstall } from '../src/install.mjs';
import { planBodyFeatureInstall } from '../src/body-feature-plan.mjs';
import { parseBodyFeatureDeclaration, MESSAGE_REACT_EMOJIS } from '../src/body-feature-grammar.mjs';
import { parseDeclaration, parseBodySetBounds } from '../src/declaration.mjs';
import { canonicalDeclaration, declarationDigest } from '../src/digest.mjs';
import { validateBodyFeaturePackage } from '../src/validate.mjs';
import { LIMITS } from '../src/limits.mjs';
import * as publicKit from '../src/index.mjs';
const oracles=JSON.parse(readFileSync(new URL('vectors/main269-feature1bad-plan-oracles.json',import.meta.url),'utf8'));
const body={need:'records.body.read.v1',scope:'viewer-visible-current-bodies'};
const sql={need:'sql.snapshot.v1',key:'grid.items',label:'Items',sql:'SELECT id FROM records ORDER BY id LIMIT 1'};
const bound={effect:'records.body-set.v1',max_body_bytes:100,target:{need:sql.key}};
const errors=p=>p.findings.filter(f=>f.severity==='error');
const refusal='body feature plans require a separately qualified Cookie host executor; runInstall refuses before source writes';

test('all eight main269 default/chunked/icon/removal plans remain exact independent oracles',()=>{
  assert.equal(oracles.main,'269dbff08890a36ef660945970665bac601627c0');
  // The oracles are the raw-body routes of main 269; the default is now gzip+base64, so pin utf8.
  for(const v of oracles.legacy) assert.deepEqual(planInstall({...v.input,bodyEncoding:'utf8'}),v.plan,v.name);
});

test('all three qualified root feature plans retain every byte except fresh UUID field',()=>{
  assert.equal(oracles.root,'1bad1ca097caf0b78d5f46a974817e40a0e5f341');
  for(const v of oracles.feature){
    const actual=JSON.parse(JSON.stringify(planBodyFeatureInstall(v.input)));
    assert.match(actual.hostInstall.arguments.idempotency_key,/^[0-9a-f-]{36}$/);
    actual.hostInstall.arguments.idempotency_key='ORIGINAL-UUID-SENTINEL';
    assert.deepEqual(actual,v.plan,v.name);
  }
});

test('KR1 recognizes only own-data feature kind before options/steps/client access or writes',async()=>{
  for(const thrown of [false,true]){
    const counts={options:0,steps:0,client:0,writes:0};
    const plan={kind:'alpha-tab.body-feature-plan.v1',get steps(){counts.steps++;throw 0;}};
    const options={get onStep(){counts.options++;if(thrown)throw 0;return ()=>{counts.writes++;};}};
    const client={get call(){counts.client++;throw 0;}};
    await assert.rejects(runInstall(plan,client,options),{message:refusal});
    assert.deepEqual(counts,{options:0,steps:0,client:0,writes:0});
  }
});

test('ordinary options binding and inherited/accessor kind remain non-feature semantics',async()=>{
  let options=0,kind=0;
  for(const plan of [Object.assign(Object.create({kind:'alpha-tab.body-feature-plan.v1'}),{steps:[]}),{get kind(){kind++;throw 0;},steps:[]}]){
    assert.deepEqual(await runInstall(plan,{call(){throw 0;}},{get onStep(){options++;return undefined;}}),{log:[]});
  }
  assert.equal(options,2);assert.equal(kind,0);
  await assert.rejects(runInstall({steps:[]},{},{get onStep(){throw new Error('ordinary options');}}),/ordinary options/);
});

test('feature parameters do not inherit main chunked/after-removal options or icon facets',()=>{
  const input=oracles.feature[0].input;
  for(const patch of [{chunked:true},{chunked:false},{afterRemovalEventId:'removed'}])assert.throws(()=>planBodyFeatureInstall({...input,...patch}),/unknown/);
  const plan=planBodyFeatureInstall({...input,descriptor:{...input.descriptor,icon:'BookOpen'}});
  assert.deepEqual(plan.sourceSteps.find(s=>s.step==='rekind-artifact').arguments.facets,{runtime:'native.html.v1'});
});

test('plain dormant BodySet keeps main semantics; structured extension combinations fail everywhere',()=>{
  const ordinary={needs:[sql],effects:[bound]};
  assert.equal(errors(parseDeclaration(ordinary)).length,0);
  assert.deepEqual(parseBodySetBounds(ordinary).bounds,[{need:'grid.items',max_body_bytes:100}]);
  assert.deepEqual(canonicalDeclaration(ordinary).effects,[bound]);
  for(const declaration of [{needs:[body,sql],effects:[bound]},{...ordinary,sessions:[]}]){
    assert.throws(()=>canonicalDeclaration(declaration),/invalid_effect/);
    assert.throws(()=>declarationDigest(declaration),/invalid_effect/);
    assert.ok(errors(parseBodyFeatureDeclaration(declaration)).length);
    const input={...oracles.feature[0].input,descriptor:{...oracles.feature[0].input.descriptor,declaration}};
    assert.equal(validateBodyFeaturePackage(input).ok,false);
    assert.throws(()=>planBodyFeatureInstall(input));
  }
});

test('literal bare BodySet discriminator: ordinary refusal versus frozen inert commitment strings',()=>{
  const plain={needs:[],effects:['records.body-set.v1']};
  assert.ok(errors(parseDeclaration(plain)).some(f=>f.rule==='body-set.shape'));
  assert.throws(()=>canonicalDeclaration(plain),/invalid_effect/);
  for(const declaration of [{...plain,sessions:[]},{needs:[body],effects:plain.effects}]){
    const canonical=canonicalDeclaration(declaration);
    assert.deepEqual(canonical.effects,['records.body-set.v1']);
    assert.equal(Object.hasOwn(canonical,'body_read_needs'),declaration.needs.length>0);
    assert.equal(Object.hasOwn(canonical,'sessions'),Object.hasOwn(declaration,'sessions'));
  }
  assert.equal(errors(parseBodyFeatureDeclaration({needs:[body],effects:plain.effects})).length,0);
});

test('canonical session-only inputs never require descriptor or ordinary feature admission',()=>{
  assert.deepEqual(canonicalDeclaration({needs:[],effects:[],sessions:[]}),{needs:[],effects:[],sessions:[]});
  assert.deepEqual(canonicalDeclaration({needs:[],effects:[]}),{needs:[],effects:[]});
  assert.notEqual(declarationDigest({needs:[],effects:[]}),declarationDigest({needs:[],effects:[],sessions:[]}));
  for(const sessions of [null,{},'absent'])assert.throws(()=>canonicalDeclaration({needs:[],effects:[],sessions}),/invalid_session/);
});

test('main mutable caps/catalogue cannot transitively affect frozen feature parser or digests',()=>{
  const input=oracles.feature[2].input, expected=oracles.feature[2].plan.digests;
  const before={...LIMITS.declaration};
  try{
    for(const key of ['max_entries','sql_snapshot_max_needs','sql_need_key_max_chars','label_max_chars','sql_max_bytes','max_params','param_text_hard_cap','param_name_max_chars','facet_set_values_max'])LIMITS.declaration[key]=0;
    LIMITS.declaration.host_need_names=['grid.items','items'];
    LIMITS.declaration.param_types=[];
    assert.equal(errors(parseBodyFeatureDeclaration(input.descriptor.declaration)).length,0);
    assert.equal(declarationDigest(input.descriptor.declaration),expected.declaration_digest);
  }finally{Object.assign(LIMITS.declaration,before);}
  assert.equal(Object.isFrozen(MESSAGE_REACT_EMOJIS),true);
});

test('main public exports remain additive without feature execution/CLI promotion',()=>{
  for(const key of ['planInstall','runInstall','createMcpClient','requestCode','verifyCode','readBearer','isIconName','isSupportedIconName','SUPPORTED_ICON_NAMES','parseBodySetBound','parseBodySetBounds','BODY_SET_EFFECT','planBodyFeatureInstall'])assert.equal(Object.hasOwn(publicKit,key),true,key);
  assert.equal(Object.hasOwn(publicKit,'prepareSourceSteps'),false);
});
