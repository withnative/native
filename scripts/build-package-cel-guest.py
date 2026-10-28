"""Fresh source-built development guest; verify pins before embedding. No host build cycle."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import shutil
import tomllib
from typing import NamedTuple

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'target/package-cel-guest'
FLAGS = '-C panic=abort -C debuginfo=0 -C link-arg=--stack-first -C link-arg=-zstack-size=1048576'
ABI = 'native.cel-scalar-guest/2'
TARGET = 'wasm32-unknown-unknown'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inputs(root=ROOT):
    paths = [root / p for p in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'scripts/build-package-cel-guest.py']]
    for crate in ['cel-subset', 'package-cel-wire', 'package-cel-guest']:
        paths.append(root / 'crates' / crate / 'Cargo.toml')
        paths += sorted(p for p in (root / 'crates' / crate).rglob('*') if p.is_file() and p.name != 'Cargo.toml' and not {'target', '.git', '__pycache__'}.intersection(p.relative_to(root / 'crates' / crate).parts))
    if (root / '.cargo/config.toml').exists():
        paths.append(root / '.cargo/config.toml')
    return [{'path': str(p.relative_to(root)), 'sha256': digest(p.read_bytes())} for p in sorted(paths)]


# Prescribed trusted guest recipe, not compiler/linker attestation. Host Cargo
# flags/wrappers are not the guest recipe, including when build.rs verifies it.
CONTROL_ENV = {'RUSTC', 'CARGO_BUILD_RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
               'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
               'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS',
               'CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS', 'RUSTC_BOOTSTRAP'}


def configuration(root):
    home = pathlib.Path(os.environ.get('CARGO_HOME', pathlib.Path.home() / '.cargo'))
    directories = [home] + [p / '.cargo' for p in reversed([root, *root.parents])]
    records = []
    seen = set()
    for directory in directories:
        # Cargo prefers legacy config over config.toml when both exist.
        path = next((directory / n for n in ['config', 'config.toml'] if (directory / n).is_file()), None)
        if path is None or path.resolve() in seen:
            continue
        seen.add(path.resolve())
        data = path.read_bytes()
        config = tomllib.loads(data.decode())
        if 'include' in config or CONTROL_ENV.intersection(config.get('env', {})) or any(k.startswith('CARGO_PROFILE_DEV_') for k in config.get('env', {})):
            raise ValueError('unsupported Cargo config include/compilation-control [env] override')
        name = 'workspace:' + str(path.relative_to(root)) if path.is_relative_to(root) else str(path.resolve())
        records.append({'path': name, 'sha256': digest(data)})
    return records


def compiler(root=ROOT, selected=None):
    selected = selected or os.environ.get('RUSTC') or os.environ.get('CARGO_BUILD_RUSTC')
    if not selected:
        selected = subprocess.check_output(['rustup', 'which', 'rustc'], cwd=root, text=True).strip()
    executable = shutil.which(selected)
    if executable is None:
        raise ValueError('selected guest compiler is not executable')
    path = pathlib.Path(executable).absolute()
    # Resolving rustc's rustup symlink directly would invoke rustup under the
    # wrong basename. Ask the proxy for its concrete compiler instead.
    if path.name == 'rustc' and path.resolve().name == 'rustup':
        path = pathlib.Path(subprocess.check_output([str(path.with_name('rustup')), 'which', 'rustc'], cwd=root, text=True).strip())
    return {'command': str(path), 'version': subprocess.check_output([str(path), '-Vv'], cwd=root, text=True).strip()}


def pins(root=ROOT, selected=None):
    if os.environ.get('RUSTC_BOOTSTRAP') or any(k.startswith('CARGO_PROFILE_DEV_') for k in os.environ):
        raise ValueError('unsupported bootstrap/dev-profile environment override for prescribed guest')
    return {'format': 'native.cel-guest-build/2', 'abi': ABI, 'target': TARGET,
            'flags': FLAGS, 'extra_rustflags': FLAGS.split(), 'wrapper_policy': 'disabled for guest only',
            'flags_scope': 'prescribed extra target flags; Cargo-generated arguments/profiles are not an exhaustive compiler argv attestation',
            'cargo_configuration': configuration(root), 'compiler': compiler(root, selected),
            'crate_type': 'cdylib', 'build_mode': 'cargo rustc --lib --crate-type cdylib --locked',
            'inputs': inputs(root)}


def guest_command(context):
    env = os.environ.copy()
    env['RUSTC'] = context['compiler']['command']
    env['CARGO_BUILD_RUSTC'] = env['RUSTC']
    env['RUSTC_WRAPPER'] = ''; env['RUSTC_WORKSPACE_WRAPPER'] = ''
    env['CARGO_BUILD_RUSTC_WRAPPER'] = ''; env['CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER'] = ''
    env.pop('RUSTFLAGS', None)
    env['CARGO_ENCODED_RUSTFLAGS'] = chr(31).join(context['extra_rustflags'])
    # Explicit compiler config overrides ancestor/home build.rustc settings;
    # forced compilation-control [env] entries are refused above.
    command = ['cargo', '--config', 'build.rustc=' + json.dumps(env['RUSTC']),
               '--config', 'build.rustc-wrapper=""', '--config', 'build.rustc-workspace-wrapper=""',
               'rustc', '--locked', '-p', 'native-package-cel-guest', '--lib', '--crate-type',
               'cdylib', '--target', TARGET, '--message-format=json-render-diagnostics']
    return command, env


class VerifiedArtifact(NamedTuple):
    manifest: dict
    module: bytes
    manifest_sha256: str


def inventory(data):
    if data[:8] != b'\0asm\x01\0\0\0':
        raise ValueError('invalid module header')
    pos = 8
    def leb():
        nonlocal pos
        value = 0
        for shift in range(0, 35, 7):
            b = data[pos]; pos += 1; value |= (b & 127) << shift
            if not b & 128:
                return value
        raise ValueError('invalid u32 LEB')
    exports = {}
    while pos < len(data):
        section = data[pos]; pos += 1
        length = leb(); end = pos + length
        if end > len(data):
            raise ValueError('truncated section')
        if section == 2 and leb() != 0:
            raise ValueError('guest imports refused')
        if section == 7:
            for _ in range(leb()):
                n = leb(); name = data[pos:pos+n].decode('utf8'); pos += n
                kind = data[pos]; pos += 1; leb()
                if name in exports:
                    raise ValueError('duplicate export')
                exports[name] = kind
            if pos != end:
                raise ValueError('export section trailing bytes')
        pos = end
    expected = {'memory': 2, 'guest_abi_version': 0, 'guest_allocate': 0, 'guest_evaluate': 0}
    if exports != expected:
        raise ValueError('unexpected export inventory')
    return {'imports': [], 'exports': exports}


def verify(directory=ARTIFACTS, root=ROOT, selected=None):
    manifest_bytes = (directory / 'build.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    actual = pins(root, selected)
    if any(manifest.get(k) != v for k, v in actual.items()):
        raise ValueError('stale guest source/lock/toolchain/flags/ABI build pins; rebuild prescribed guest')
    data = (directory / 'guest.wasm').read_bytes()
    if manifest.get('module_length') != len(data) or manifest.get('module_sha256') != digest(data) or manifest.get('inventory') != inventory(data):
        raise ValueError('guest module digest/inventory mismatch')
    return VerifiedArtifact(manifest, data, digest(manifest_bytes))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--verify-only', action='store_true')
    p.add_argument('--embed-out', type=pathlib.Path)
    p.add_argument('--compiler', help='effective compiler; host build.rs passes Cargo-provided RUSTC')
    args = p.parse_args()
    if not args.verify_only and args.embed_out is None:
        before = pins(selected=args.compiler)
        command, env = guest_command(before)
        artifacts = []
        with subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, text=True) as process:
            for line in process.stdout:
                message = json.loads(line)
                if message.get('reason') == 'compiler-message':
                    print(message['message'].get('rendered',''),end='')
                if message.get('reason') == 'compiler-artifact' and message.get('target',{}).get('name') == 'native_package_cel_guest':
                    if pathlib.Path(message['target']['src_path']).resolve() != ROOT/'crates/package-cel-guest/src/lib.rs':
                        raise ValueError('unexpected guest artifact source')
                    artifacts += [pathlib.Path(name) for name in message['filenames'] if name.endswith('.wasm')]
            if process.wait() != 0:
                raise ValueError('guest compiler failed')
        if len(artifacts) != 1:
            raise ValueError('guest compiler did not identify exactly one Wasm artifact')
        if before != pins(selected=before['compiler']['command']):
            raise ValueError('guest inputs changed during build')
        data = artifacts[0].read_bytes()
        manifest = {**before, 'module_length': len(data), 'module_sha256': digest(data), 'inventory': inventory(data)}
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        (ARTIFACTS / 'guest.wasm').write_bytes(data)
        (ARTIFACTS / 'build.json').write_text(json.dumps(manifest, indent=2) + '\n')
    verified = verify(selected=args.compiler)
    manifest, data = verified.manifest, verified.module
    manifest_digest = verified.manifest_sha256
    source_digest = digest(json.dumps(manifest['inputs'], sort_keys=True, separators=(',', ':')).encode())
    if args.embed_out is not None:
        args.embed_out.mkdir(parents=True, exist_ok=True)
        # Embed exactly the verified byte buffer, not a second mutable source read.
        (args.embed_out / 'guest.wasm').write_bytes(data)
        constants = {'BUILD_MANIFEST_SHA256': manifest_digest, 'GUEST_SOURCE_SHA256': source_digest,
                     'GUEST_MODULE_SHA256': manifest['module_sha256'],
                     'GUEST_ROOT_LOCK_SHA256': next(p['sha256'] for p in manifest['inputs'] if p['path'] == 'Cargo.lock')}
        constants['GUEST_LENGTH'] = len(data)
        constants['GUEST_ABI'] = manifest['abi']
        constants['CARGO_CONFIG_FILES'] = [str(ROOT / p['path'][10:]) if p['path'].startswith('workspace:') else p['path'] for p in manifest['cargo_configuration']]
        (args.embed_out / 'pins.json').write_text(json.dumps(constants))
    print(json.dumps({'module_sha256': manifest['module_sha256'], 'source_sha256': source_digest,
                      'build_manifest_sha256': manifest_digest, 'inventory': manifest['inventory']}))


if __name__ == '__main__':
    main()
