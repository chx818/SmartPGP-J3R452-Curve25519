"""Deterministic CAP container and public build-input provenance helpers.
No card I/O or production-specific paths. Python standard library only.
"""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = 'tools/toolchain-lock.json'
BUILD_INPUTS = (
    'tools/build_verified.py', 'tools/release_support.py', 'tools/verify_release.py',
    LOCK_PATH, 'build.xml', 'build.bat', 'build.ps1',
)
FIXED_DATE = (2000, 1, 1, 0, 0, 0)
FIXED_CREATION = b'Sat Jan 01 00:00:00 UTC 2000'
MANIFEST_NAME = 'META-INF/MANIFEST.MF'

class ReleaseError(RuntimeError):
    pass

def digest(data):
    return hashlib.sha256(data).hexdigest()

def text_bytes(path):
    return Path(path).read_bytes().replace(b'\r\n', b'\n')

def stable_json(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True)+'\n').encode('utf-8')

def local_path(root, name):
    p = PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name or not name or str(p) != name:
        raise ReleaseError('Unsafe relative input name: '+repr(name))
    out = (Path(root)/name).resolve()
    if not out.is_relative_to(Path(root).resolve()):
        raise ReleaseError('Input escaped source directory: '+name)
    return out

def load_lock(root=ROOT):
    lock = json.loads((Path(root)/LOCK_PATH).read_text(encoding='utf-8-sig'))
    if lock.get('schema') != 1 or lock.get('target') != '3.0.5':
        raise ReleaseError('Unsupported toolchain lock')
    if lock.get('canonical_cap') != {'schema':1, 'timestamp':list(FIXED_DATE),
                                    'manifest_creation_time':FIXED_CREATION.decode(),
                                    'compression':'ZIP_STORED', 'entry_order':'lexicographic'}:
        raise ReleaseError('Unexpected canonicalization policy')
    deps = lock['dependencies_sha256']
    if not lock['java_tool_classpath'] or len(set(lock['java_tool_classpath'])) != len(lock['java_tool_classpath']):
        raise ReleaseError('Invalid Java tool classpath')
    for name in [*deps, *lock['java_tool_classpath']]:
        local_path(root, name)
    if not set(lock['java_tool_classpath']).issubset(deps):
        raise ReleaseError('Unlocked Java tool classpath')
    return lock

def input_inventory(root=ROOT):
    root = Path(root)
    lock = load_lock(root)
    sources = sorted(p.relative_to(root).as_posix() for p in (root/'src').rglob('*.java'))
    if not sources:
        raise ReleaseError('No applet sources')
    result = {'source_sha256': {n:digest(text_bytes(local_path(root,n))) for n in sources},
              'build_tools_sha256': {n:digest(text_bytes(local_path(root,n))) for n in BUILD_INPUTS},
              'dependencies': {n:digest(local_path(root,n).read_bytes()) for n in sorted(lock['dependencies_sha256'])}}
    if result['dependencies'] != lock['dependencies_sha256']:
        changed = [n for n,h in result['dependencies'].items() if lock['dependencies_sha256'].get(n)!=h]
        raise ReleaseError('Locked dependency changed: '+', '.join(changed))
    # The loaded wrapper is not compiled here; its distributed copies must be identical.
    if (root/'prebuilt/Curve25519.cap').read_bytes() != (root/'lib/Curve25519.cap').read_bytes():
        raise ReleaseError('Curve25519 prebuilt/lib copies differ')
    return result

def git(root, *args):
    proc = subprocess.run(['git','-C',str(root),*args],capture_output=True)
    if proc.returncode:
        raise ReleaseError('Git provenance check failed: '+proc.stderr.decode('utf-8',errors='replace').strip())
    return proc.stdout

def head_commit(root=ROOT):
    return git(root,'rev-parse','HEAD').decode().strip()

def verify_source_commit(root, commit, inventory, require_ancestor=True):
    if not re.fullmatch(r'[0-9a-f]{40}',commit):
        raise ReleaseError('Expected a full source commit object ID')
    if git(root,'rev-parse',commit+'^{commit}').decode().strip() != commit:
        raise ReleaseError('Invalid source commit')
    if require_ancestor:
        git(root,'merge-base','--is-ancestor',commit,'HEAD')
    files = set(git(root,'ls-tree','-r','--name-only',commit,'--','src').decode().splitlines())
    java_files = {n for n in files if n.endswith('.java')}
    if java_files != set(inventory['source_sha256']):
        raise ReleaseError('Working Java source set differs from source commit (including untracked/missing Java files)')
    for group in ('source_sha256','build_tools_sha256','dependencies'):
        for name, expected in inventory[group].items():
            data = git(root,'show',commit+':'+name)
            if group != 'dependencies':
                data = data.replace(b'\r\n',b'\n')
            if digest(data) != expected:
                raise ReleaseError('Build input differs from source commit: '+name)

def verify_jdk(jdk, lock):
    jdk = Path(jdk).resolve()
    expected = lock['jdk']['files_sha256']
    # Reject extra/missing binaries or config in the reference distribution, not only java.exe.
    actual_names = {p.relative_to(jdk).as_posix() for p in jdk.rglob('*') if p.is_file()}
    if actual_names != set(expected):
        raise ReleaseError('JDK distribution file set differs from toolchain lock')
    for name, checksum in expected.items():
        if digest(local_path(jdk,name).read_bytes()) != checksum:
            raise ReleaseError('JDK file differs from lock: '+name)
    return {'vendor':lock['jdk']['vendor'], 'version':lock['jdk']['version'],
            'files_sha256':expected}

def normalized_manifest(data):
    # Exactly one narrowly named attribute; no payload/other attribute normalization.
    pattern = rb'(?m)^Java-Card-CAP-Creation-Time: [^\r\n]*(?=\r?$)'
    result, count = re.subn(pattern,b'Java-Card-CAP-Creation-Time: '+FIXED_CREATION,data)
    if count != 1:
        raise ReleaseError('Expected exactly one CAP creation-time manifest attribute')
    return result

def cap_entries(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        if len(names)!=len(set(names)):
            raise ReleaseError('Duplicate ZIP entry')
        if MANIFEST_NAME not in names:
            raise ReleaseError('CAP manifest is missing')
        entries = {}
        for info in z.infolist():
            name = info.filename
            path = PurePosixPath(name.rstrip('/'))
            if path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name or not path.parts:
                raise ReleaseError('Unsafe CAP entry name')
            if info.flag_bits & 1:
                raise ReleaseError('Encrypted CAP archives are unsupported')
            entries[name] = z.read(info)
        if not any(n.endswith('/Header.cap') for n in names):
            raise ReleaseError('CAP Header is missing')
        return entries

def canonical_cap(data):
    entries = cap_entries(data)
    entries[MANIFEST_NAME] = normalized_manifest(entries[MANIFEST_NAME])
    output = io.BytesIO()
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_STORED,allowZip64=False) as z:
        z.comment=b''
        for name in sorted(entries):
            info=zipfile.ZipInfo(name,FIXED_DATE)
            info.compress_type=zipfile.ZIP_STORED
            info.create_system=0
            info.create_version=20
            info.extract_version=20
            info.flag_bits=0
            info.internal_attr=0
            info.external_attr=(0o100644 << 16) if not name.endswith('/') else ((0o40755 << 16)|0x10)
            info.extra=b''
            info.comment=b''
            z.writestr(info,entries[name])
    result=output.getvalue()
    final=cap_entries(result)
    if final!=entries:
        raise ReleaseError('CAP payload changed during packaging')
    return result

def entry_hashes(data):
    return {n:digest(payload) for n,payload in sorted(cap_entries(data).items())}

def checksums(cap_hash):
    return f'{cap_hash}  dist/SmartPGPApplet.cap\n{cap_hash}  prebuilt/SmartPGPApplet.cap\n'.encode('ascii')

def verify_release(root=ROOT, check_git=True):
    root=Path(root)
    manifest=json.loads((root/'dist/build-manifest.json').read_text(encoding='utf-8-sig'))
    if manifest.get('schema')!=2:
        raise ReleaseError('Release is not in reproducible-build format; build a release first')
    inventory=input_inventory(root)
    for group in inventory:
        if manifest.get(group)!=inventory[group]:
            raise ReleaseError('Release inputs do not match current checkout: '+group)
    lock=load_lock(root)
    if manifest.get('package_version')!=lock['package_version'] or manifest.get('target')!=lock['target']:
        raise ReleaseError('Release target/version differs from lock')
    expected_jdk={'vendor':lock['jdk']['vendor'],'version':lock['jdk']['version'],'files_sha256':lock['jdk']['files_sha256']}
    if manifest.get('jdk')!=expected_jdk or manifest.get('canonicalization')!=lock['canonical_cap']:
        raise ReleaseError('Release JDK/canonicalization differs from lock')
    cap=(root/'dist/SmartPGPApplet.cap').read_bytes()
    if cap!=(root/'prebuilt/SmartPGPApplet.cap').read_bytes():
        raise ReleaseError('dist/prebuilt are not byte-for-byte identical')
    if digest(cap)!=manifest['cap_sha256']:
        raise ReleaseError('Whole CAP hash mismatch')
    if canonical_cap(cap)!=cap:
        raise ReleaseError('CAP is not in the canonical release format')
    hashes=entry_hashes(cap)
    if hashes!=manifest.get('cap_entries_sha256') or {n:h for n,h in hashes.items() if n.endswith('.cap')}!=manifest.get('cap_components_sha256'):
        raise ReleaseError('CAP payload hash mismatch')
    if (root/'dist/SHA256SUMS').read_bytes()!=checksums(manifest['cap_sha256']):
        raise ReleaseError('SHA256SUMS mismatch')
    if check_git:
        verify_source_commit(root,manifest['source_commit'],inventory)
    return manifest
