"""Generate bounded, actual Stage3 development evidence; never embeds executable bytes."""
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import tomllib

ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=ROOT/'target/package-cel-guest-stage3'
BASE='6f9be45b12f38eee76bdcca14a98d0b4e04baf42'
spec=importlib.util.spec_from_file_location('guest_build',ROOT/'scripts/build-package-cel-guest.py')
build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)
verified=build.verify()
manifest,module=verified.manifest,verified.module
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
host=json.loads((OUT/'host-boundary-receipt.json').read_text())
cli=json.loads((OUT/'cli-receipts.json').read_text())
assert host['stage']==3 and host['owned_threads_after_shutdown']==0
assert len(host['rows'])==96 and len(cli)==2
assert [row['outcome']['result']['value'] for row in cli]==[900,True]
manifest_sha=verified.manifest_sha256
for row in cli:
    execution=row['outcome']['receipt']['execution'];g=execution['guest']
    assert execution['language']=='cel-subset@1' and execution['policy']=='cel-subset@1/p1' and execution['interim']
    assert g['abi']==manifest['abi'] and g['module_sha256']==manifest['module_sha256']
    assert g['build_manifest_sha256']==manifest_sha and g['runtime']=='wasmtime@49.0.1'
    assert g['configuration']=='native.cel-guest-dev-host/3' and g['phase']=='Deliver'
    assert 0<g['fuel_used']<=g['fuel_budget']==50_000_000
for row in host['rows']:
    if 'fresh_CEL_recovery' in row:
        r=row['fresh_CEL_recovery'];assert r['module_sha256']==manifest['module_sha256'] and r['report']['value']==2 and r['failure'] is None
# No language/policy/fence changes, including Stage1/2 historical proof files.
subprocess.run(['git','diff','--exit-code',BASE,'--','crates/cel-subset','src/kernel.rs','src/package_operations.rs','src/package_manifest.rs','experiments/package-cel-guest'],cwd=ROOT,check=True)
old=tomllib.loads(subprocess.check_output(['git','show',BASE+':Cargo.lock'],cwd=ROOT).decode())
new=tomllib.loads((ROOT/'Cargo.lock').read_text())
def versions(lock):return {(p['name'],p['version'],p.get('source'),p.get('checksum')) for p in lock['package']}
a,b=versions(old),versions(new);assert a<=b
paths=[ROOT/'Dockerfile',ROOT/'scripts/tests/test_docker_ci_contract.py',ROOT/'scripts/tests/test_package_cel_guest_build.py',ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'rust-toolchain.toml',ROOT/'src/kernel.rs',ROOT/'src/package_manifest.rs',ROOT/'src/package_operations.rs',ROOT/'src/package_cel_dev.rs',ROOT/'tests/kernel/package_cel_dev_smoke.rs',ROOT/'ci/test-gates.toml',ROOT/'ci/test-map.json',ROOT/'native-ce-boundary.json']
paths+=list((ROOT/'src/package_cel_dev').rglob('*.rs'))
for name in ['wire','guest','host']:
    paths += [p for p in (ROOT/'crates'/('package-cel-'+name)).rglob('*') if p.is_file() and p.suffix in ['.rs','.toml','.wat','.md']]
paths += [ROOT/'scripts'/n for n in ['build-package-cel-guest.py','package-cel-guest-guard.py','package-cel-guest-receipt.py']]
paths += [ROOT/'.github/workflows'/n for n in ['ci.yml','ci-package-cel-dev.yml','ci-all-features-defence.yml']]
entries=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in sorted(set(paths))]
source=''.join(e['path']+'\0'+e['sha256']+'\n' for e in entries).encode()
(OUT/'source-manifest.json').write_text(json.dumps(entries,indent=2)+'\n')
expected_cases={'corrections-wire-proof':1,'corrections-guest-native-proof':3,'corrections-host-current-proof':1,'corrections-root-runtime-proof':12,'corrections-delivery-proof':2,'corrections-cli-proof':1,'corrections-shipping-proof':1}
for label,count in expected_cases.items():
    assert re.search(r'test result: ok\. '+str(count)+r' passed;', (OUT/(label+'.log')).read_text()), label
labels=['corrections-wire-proof','corrections-guest-native-proof','corrections-guest-profile-build','corrections-normalized-final-build','corrections-root-check','corrections-libraries-current-compile','corrections-host-current-proof','corrections-host-clippy-final','corrections-root-runtime-proof','corrections-delivery-proof','corrections-shipping-proof','corrections-cli-build','corrections-cli-proof']
commands=[]
for label in labels:
    p=OUT/(label+'.json');r=json.loads(p.read_text());assert r['exit_code']==0 and 'guard_stop' not in r
    commands.append({'receipt':str(p.relative_to(ROOT)),'receipt_sha256':sha(p),'log_sha256':sha(OUT/(label+'.log')),**r})
receipt={'stage':3,'base_reviewed_stage2':BASE,'source_digest':hashlib.sha256(source).hexdigest(),'source_digest_algorithm':'sha256 of sorted relative-path + NUL + file-sha256 + LF','root_lock_sha256':sha(ROOT/'Cargo.lock'),'all_existing_root_package_selections_preserved':True,'added_packages':sorted((p[0],p[1]) for p in b-a),'guest_build':manifest,'guest_build_manifest_sha256':manifest_sha,'embedding_correction':{'previous_head':'b0921526852aea98ca1930b3e3873aa3fe26e2a8','prior_boundary_refusal':'target/package-cel-guest-stage3/source-boundary.log','first_symbol_refusal':'target/package-cel-guest-stage3/embedding-host-first-symbol-refusal.log','development_cases':20,'shipping_cases':1,'additional_lint_finding':{'receipt':'target/package-cel-guest-stage3/embedding-host-clippy.json','status':'original failure preserved; resolved by private ExecutionLimits grouping','scope':'dispatch fuel/timeout grouped without changing values/order/test hooks/permit semantics','runtime_unchanged_by_embedding':True,'resolution_clippy':'target/package-cel-guest-stage3/cleanup-host-clippy.json','resolution_host_matrix':'target/package-cel-guest-stage3/cleanup-host-proof.json'},'mechanism':'verified read-only native object in static archive; fixed extern array; no dynamic Rust includes','cross_platform_execution':'Linux x86_64 executed; six object encodings/readbacks only'},'review_corrections':{'reviewed_head':'db74b20ffa57f233d6644a3f832aac25d3699541','findings':['Docker member/build-script stubs','effective compiler selection','single validated manifest snapshot'],'compiler_probe':json.loads((OUT/'corrections-provenance-independent-probe.json').read_text()),'normalization_probe':json.loads((OUT/'corrections-normalization-final-probe.json').read_text()),'held_lock':json.loads((OUT/'corrections-held-lock-comparison.json').read_text())},'validation_scope':{'current':'fresh 20 development +1 shipping cases against new format2 provenance/guest pins; fresh96 host rows and all-target Clippy','prior_evidence':'db74/dbd/b092 logs and original independent failed probes preserved separately','qualification':'no held host build/UI proof, image build, full local gate or review clearance'},'host_matrix':host,'cli_receipts':cli,'commands':commands,'known_harness_timeout':json.loads((OUT/'build-lock-timeout-diagnosis.json').read_text()),'qualification':'Explicit local development only; P1 interim, reduced protocol parity excludes checked API caps/load cost/budget scope/cost/input cost. Host compilation/native allocations outside guest caps. No native CEL fallback, production containment qualification, new browser proof, hosted activation, full local gate or publication. Stage1/2 proof/history preserved.'}
encoded=json.dumps(receipt,indent=2)+'\n';assert len(encoded.encode())<256*1024
(ROOT/'crates/package-cel-host/stage3-receipt.json').write_text(encoded)
print(json.dumps({'module_sha256':manifest['module_sha256'],'source_digest':receipt['source_digest'],'host_rows':96,'CLI_packages':2,'bytes':len(encoded.encode())}))
