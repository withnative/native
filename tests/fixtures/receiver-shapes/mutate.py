#!/usr/bin/env python3
"""Bounded source mutants; compilation must succeed and exactly one test must fail.

Requires a clean committed tree, restores each source file in finally, and
records exact head/source hashes plus the assertion failure. No artifact from
a mutated build may be packaged or used as a serving binary.
"""
from pathlib import Path
import subprocess, hashlib, json, re, signal, sys, time
ROOT=Path(__file__).resolve().parents[3]; EVIDENCE=ROOT/'target/agent-evidence/receiver-shape-mutations';EVIDENCE.mkdir(parents=True,exist_ok=True)
subprocess.run(['git','diff','--quiet','HEAD','--'],cwd=ROOT,check=True)
os_module=__import__('os');os_module.chdir(ROOT)
def interrupt(*_): raise KeyboardInterrupt
signal.signal(signal.SIGTERM,interrupt)
def replace_once(source,old,new):
 assert source.count(old)==1,(old,source.count(old));return source.replace(old,new,1)
def parity(source):
 a=source.index('        let projection = columns',source.index('async fn verify_database_successor_contents'))
 b=source.index('        if !added.is_empty()',a)
 return source[:b]+'        let projection = "*";\n'+source[b:]
def exact_true(source):
 a=source.index('fn exact(');b=source.index('\npub(super) fn no_observation_pair',a)
 return source[:a]+'fn exact(_actual: &NodeHoldingContract, _frozen: &NodeHoldingContract) -> bool { true }\n'+source[b:]
def disable_v1(source):
 return replace_once(source,'        if dialect.is_err() {','        if false && dialect.is_err() {')
def scope_bypass(source):
 return replace_once(source,'        if manifest.hosted_route_database_id != self.expected_route_id\n            || self\n                .expected_origin_id\n                .as_ref()\n                .is_some_and(|id| id != &manifest.origin_database_id)\n', '        if false\n')
def writable_serving_pool(source):
 a=source.index('async fn open_standby_read_pool(');b=source.index('\n/// Open a database.',a)
 body=source[a:b]
 body=replace_once(body,'install_enrolled_guard(connection, true)', 'install_enrolled_guard(connection, false)')
 body=replace_once(body,'read_only_connect_options(path)?', 'SqliteConnectOptions::new().filename(path).create_if_missing(false)')
 return source[:a]+body+source[b:]
def rebind_primary(source):
 a=source.index('    let primary_supported = if ')
 b=source.index('    if !primary_supported',a)
 return source[:a]+'    let primary_supported = observed.engine_schema_version == manifest.consumer.engine_schema_version;\n'+source[b:]
def probe_maintenance(source):
 a=source.index('impl AuthorityActHttpClient for ProbeHttp')
 return source[:a]+replace_once(source[a:],'            if response\n                .headers()','            if false && response\n                .headers()')
cases=[
 ('installed-fresh-codec-bypass','src/node/gate.rs',lambda s:replace_once(s,'            let paired = legacy_append\n                && self','            let paired = true\n                && self'),['node::failover::tests::default_reads::receiver_working_ingress_pairs_only_the_actual_legacy_note_codec']),
 ('installed-retained-version-bypass','src/node/gate/v2_holding.rs',lambda s:replace_once(s,'                    let paired = entry.version == super::super::journal::INSTALLED_WORKING_VERSION\n','                    let paired = true\n'),['node::gate::tests::body_merge_real_home_tests::v2_holding_tests::receiver_retained_v9_update_cannot_use_v7_digest_pair']),
 ('compiled-primary-parity-functional','src/standby_snapshot.rs',lambda s:replace_once(s,'        crate::standby::shapes::manifest(self).is_none()','        self.engine.schema_version != crate::CURRENT_ENGINE_SCHEMA_VERSION || self.kernel_v2.as_ref().is_some_and(|k| k.schema_sha256 != crate::standby::kernel_v2::KERNEL_V2_READER_SCHEMA_SHA256)'),['standby::generation_store::receiver_shape_tests::receiver_shape_full_switch_rebind_and_pin']),
 ('star-prefix','src/standby/generation_store.rs',parity,['standby::refresh::tests::kernel_v2_refresh::receiver_shape_transition_from_advanced_copy_uses_full_and_hands_off']),
 ('v1-prewriter-zero-writer-bypass','src/standby/refresh.rs',disable_v1,['standby::refresh::tests::receiver_shapes::real95_v1_cut_without_selection_refuses_before_writer_and_keeps94']),
 ('custody-pair-disabled','src/node/gate/receiver_contracts.rs',lambda s:replace_once(s,'    exact(original, old)\n','    false && exact(original, old)\n'),['node::gate::tests::body_merge_real_home_tests::v2_holding_tests::receiver_custody_three_ordinary94_calls_restart_and_drain_under95_discovery','node::gate::tests::body_merge_real_home_tests::v2_holding_tests::receiver_v7_original94_digest_none_restart_drain_and_retry_under95_discovery']),
 ('custody-hosted-descriptor-bypass','src/node/gate/receiver_contracts.rs',lambda s: replace_once(s,'        && exact(hosted, new)','        && true'),['node::gate::tests::body_merge_real_home_tests::v2_holding_tests::receiver_custody_pairs_are_complete_exact_and_argument_bounded']),
 ('audit-canonical-opener','src/standby/generation_store.rs',lambda s:replace_once(s,'    let db = crate::db::open_receiver_fork_at(scratch).await?;', '    let db = crate::open_database_at(scratch).await?;'),['standby::generation_store::receiver_shape_tests::receiver_real95_v1_audit_uses_only_disposable_registered_scratch']),
 ('pretransfer-disk-bypass','src/standby/refresh/shape_transition.rs',lambda s:replace_once(s,'        if available < needed {','        if false && available < needed {'),['standby::refresh::tests::kernel_v2_refresh::receiver_transition_disk_budget_refuses_before_range_or_page_tail']),
 ('publication-disk-bypass','src/standby/generation_store/shape_pin.rs',lambda s:replace_once(s,'        if available < needed {','        if false && available < needed {'),['standby::generation_store::receiver_shape_tests::receiver_v1_exact95_full_keeps94_while_unknown96_refuses']),
 ('route-origin-bypass','src/standby/generation_store.rs',scope_bypass,['standby::generation_store::receiver_shape_tests::receiver95_configured_origin_route_and_read_only_handles_remain_fenced']),
 ('serving-pools-writable','src/db.rs',writable_serving_pool,['standby::generation_store::receiver_shape_tests::receiver95_configured_origin_route_and_read_only_handles_remain_fenced']),
 ('unknown-v2-digest-bypass','src/standby/shapes.rs',lambda s:replace_once(s,'            && e.schema_sha256 == schema','            && true'),['standby::refresh::tests::kernel_v2_refresh::receiver_unknown_owned_shape_goes_full_without_opening_local_writer']),
 ('node-probe-selection-bypass','src/node/failover.rs',lambda s:replace_once(s,'            let selected = crate::standby::delta_transport::selected_header(response.headers())?;','            let selected = None;'),['node::failover::tests::receiver_node_probe_preserves_selected_shape_and_maintenance_boundaries']),
 ('node-probe-maintenance-bypass','src/node/failover.rs',probe_maintenance,['node::failover::tests::receiver_node_probe_preserves_selected_shape_and_maintenance_boundaries']),
 ('working-suffix-bypass','src/projector/mod.rs',lambda s:replace_once(s,'        finish_kernel_event_projection(conn, event).await\n','        Ok(())\n'),['standby::generation_store::receiver_shape_tests::receiver_real95_working_fold_after_private_ddl']),
 ('closed95-decoder-disabled','src/kernel/app_installs/consent/actions.rs',lambda s:replace_once(s,'    if !observation_envelope {','    if observation_envelope || !observation_envelope {'),['standby::generation_store::receiver_shape_tests::receiver_real95_producer_full_and_delta_projection_equal_source']),
 ('local-receipt-disclosure-bypass','src/standby/shapes.rs',lambda s:replace_once(s,'        changed |= object.remove(key).is_some();','        changed |= object.contains_key(key);'),['standby::generation_store::receiver_shape_tests::receiver_real95_producer_full_and_delta_projection_equal_source']),
 ('rebind-primary-equality','src/standby/generation_store/consumer_rebind.rs',rebind_primary,['standby::generation_store::receiver_shape_tests::receiver_shape_full_switch_rebind_and_pin']),
 ('pin-delete-bypass','src/standby/generation_store.rs',lambda s:replace_once(s,'        if self.shape_pin_contains(id)? {','        if false && self.shape_pin_contains(id)? {'),['standby::generation_store::receiver_shape_tests::receiver_shape_full_switch_rebind_and_pin']),
 ('stale-episode-cooldown-bypass','src/standby/refresh.rs',lambda s:replace_once(s,'                || progress.transition\n','                || probe_base.as_ref().map(|current| self.transition_eligible(current)).transpose().map_err(local_io)?.flatten().is_some()\n'),['standby::refresh::tests::kernel_v2_refresh::receiver_stale_episode_cannot_waive_an_unrelated_full_cooldown']),
 ('transition-cap-bypass','src/standby/refresh/shape_transition.rs',lambda s:replace_once(s,'            n if n >= CAP =>','            n if n >= CAP + 1 =>'),['standby::refresh::shape_transition::tests::transition_budget_survives_head_changes_and_caps_retries']),
 ('compiled-emission95','src/db.rs',lambda s:replace_once(s,'pub const CURRENT_ENGINE_SCHEMA_VERSION: i64 = 94;','pub const CURRENT_ENGINE_SCHEMA_VERSION: i64 = 95;'),['standby::shapes::tests::compiled_emission_is_an_exact_registry_member']),
]
if len(sys.argv)>1:
 requested=set(sys.argv[1:]);known={case[0] for case in cases}
 assert requested<=known,('unknown mutation selection',sorted(requested-known))
 cases=[case for case in cases if case[0] in requested]
assert cases,'no mutation selected'
receipts=[]
for name,relative,mutate,tests in cases:
 path=ROOT/relative;original=path.read_bytes();changed=mutate(original.decode()).encode();assert changed!=original
 receipt={'mutation':name,'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'path':relative,'original_sha256':hashlib.sha256(original).hexdigest(),'mutant_sha256':hashlib.sha256(changed).hexdigest(),'tests':[]}
 try:
  path.write_bytes(changed)
  with (EVIDENCE/f'{name}-compile.log').open('wb') as log, (EVIDENCE/f'{name}-compile.jsonl').open('w') as artifacts:
   result=subprocess.run(['cargo','test','-p','native-ce','--lib','--features','v2-kernel-probe','--no-run','--message-format=json'],stdout=artifacts,stderr=log)
  assert result.returncode==0, f'{name}: compile failure is not a witness'
  artifacts=[json.loads(line) for line in (EVIDENCE/f'{name}-compile.jsonl').read_text().splitlines() if line.startswith('{')]
  binaries=[a['executable'] for a in artifacts if a.get('reason')=='compiler-artifact' and a.get('executable') and a['target']['name']=='native_ce']
  assert len(binaries)==1,binaries
  binary=binaries[0]
  for test in tests:
   with (EVIDENCE/f'{name}-{test.rsplit("::",1)[-1]}.log').open('wb') as log:
    result=subprocess.run([binary,test,'--exact','--test-threads=1'],stdout=log,stderr=subprocess.STDOUT,env={**__import__('os').environ,'RUST_MIN_STACK':'67108864'},timeout=180)
   output=(EVIDENCE/f'{name}-{test.rsplit("::",1)[-1]}.log').read_text()
   assert result.returncode!=0 and 'test result: FAILED. 0 passed; 1 failed;' in output,(name,test,result.returncode,output[-1200:])
   receipt['tests'].append({'test':test,'exit':result.returncode,'result':'expected assertion failure','failure':output[output.index('---- '):][-3500:]})
  receipt['result']='bypass fails'
 finally:
  path.write_bytes(original)
  (EVIDENCE/f'{name}.json').write_text(json.dumps(receipt,indent=2)+'\n')
 receipts.append(receipt)
 print(json.dumps({'mutation':name,'result':receipt['result']}),flush=True)
(EVIDENCE/'batch.json').write_text(json.dumps(receipts,indent=2)+'\n')
