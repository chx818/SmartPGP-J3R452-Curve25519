"""Two independent, pinned builds. Publish only byte-identical, verified CAPs.
--check-release rebuilds and compares without changing the published release.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

from release_support import (ROOT, ReleaseError, canonical_cap, checksums, digest, entry_hashes,
                             head_commit, input_inventory, load_lock, local_path, stable_json,
                             text_bytes, verify_jdk, verify_release, verify_source_commit)

if hasattr(sys.stdout,'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


def extract(file, target, accept, strip_prefix=''):
    with zipfile.ZipFile(file) as z:
        names=[n for n in z.namelist() if accept(n)]
        if len(names)!=len(set(names)):
            raise ReleaseError('Duplicate input archive entry')
        for name in names:
            dest=local_path(target,name[len(strip_prefix):])
            if dest.exists():
                raise ReleaseError('Conflicting extracted input: '+name)
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(z.read(name))


def clean_environment():
    env=os.environ.copy()
    # Prevent invisible Java options, agents, annotation processors or alternate classpaths.
    for name in list(env):
        if name.upper() in {'JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH','JAVA_HOME','JDK_JAVAC_OPTIONS'}:
            env.pop(name)
    env.update(TZ='UTC',LANG='C',LC_ALL='C',SOURCE_DATE_EPOCH='946684800')
    return env


def build_one(root, jdk, run, lock, inventory, label):
    api=run/'api';api.mkdir()
    classes=run/'classes';classes.mkdir()
    output=run/'out';output.mkdir()
    exports=run/'exports';exports.mkdir()
    # Snapshot every actual input into this run, checked against the recorded inventory.
    for group in ('source_sha256','dependencies'):
        for name,checksum in inventory[group].items():
            original=local_path(root,name)
            data=text_bytes(original) if group=='source_sha256' else original.read_bytes()
            if digest(data)!=checksum:
                raise ReleaseError('Input changed before snapshot: '+name)
            dest=local_path(run,name);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
    for name in ('sdks/jc305u3_kit/lib/api_classic.jar','lib/curve25519.jar'):
        extract(run/name,api,lambda n:n.endswith(('.class','.exp')))
    kit='sdks/jc310r20210706_kit/lib/tools.jar'
    prefix='api_export_files_3.0.5/'
    extract(run/kit,exports,lambda n:n.startswith(prefix) and n.endswith('.exp'),prefix)
    cp=os.pathsep.join(str(run/n) for n in lock['java_tool_classpath'])
    java=[str(jdk/'bin/java.exe'),'-Duser.language=en','-Duser.country=US','-Duser.timezone=UTC','-Dfile.encoding=UTF-8','-cp',cp]
    logs=[]
    def call(command):
        proc=subprocess.run(list(map(str,command)),cwd=run,env=clean_environment(),capture_output=True)
        text=(proc.stdout+proc.stderr).decode('utf-8',errors='replace')
        logs.append(text)
        (run/'build.log').write_text('\n'.join(logs),encoding='utf-8')
        print(f'[{label}] {Path(str(command[0])).name}: exit {proc.returncode}',flush=True)
        if proc.returncode:
            print(text)
            raise ReleaseError('Build/verification failed; release unchanged. Log: '+str(run/'build.log'))
    # Stable order for classes, exports and tool JARs; do not depend on directory enumeration.
    sources=[run/n for n in sorted(inventory['source_sha256'],key=str.casefold)]
    call([jdk/'bin/javac.exe','-J-Duser.language=en','-J-Duser.country=US','-J-Duser.timezone=UTC',
          '-J-Dfile.encoding=UTF-8','-proc:none','-encoding','UTF-8','-source','7','-target','7','-g',
          '-classpath',api,'-d',classes,*sources])
    def aid(value):return ':'.join('0x'+value[i:i+2] for i in range(0,len(value),2))
    call(java+['com.sun.javacard.converter.Main','-target',lock['target'],'-classdir',classes,
               '-exportpath',str(exports)+os.pathsep+str(api),'-applet',aid(lock['applet_aid']),
               lock['applet_class'],'-d',output,'-out','CAP','EXP',lock['package_name'],
               aid(lock['package_aid']),lock['package_version']])
    original=output/(lock['package_name'].replace('.','/')+'/javacard/smartpgp.cap')
    exp=sorted([*exports.rglob('*.exp'),*api.rglob('*.exp')],key=lambda p:p.as_posix())
    verifier=java+['com.sun.javacard.offcardverifier.Verifier','-target',lock['target'],*exp]
    call(verifier+[original])
    canonical=run/'SmartPGPApplet.cap'
    canonical.write_bytes(canonical_cap(original.read_bytes()))
    # Validate the exact artifact that will be distributed, not only its pre-normalized input.
    call(verifier+[canonical])
    return canonical


def publish(root, cap, manifest):
    # A reader treats manifest/checksum mismatches as failure, including during interrupted copies.
    # Prepare replacements first, and replace the manifest last (release commit marker).
    contents={'dist/SmartPGPApplet.cap':cap,'prebuilt/SmartPGPApplet.cap':cap,
              'dist/SHA256SUMS':checksums(manifest['cap_sha256']),
              'dist/build-manifest.json':stable_json(manifest)}
    prepared=[]
    try:
        for name,data in contents.items():
            dst=root/name;dst.parent.mkdir(parents=True,exist_ok=True)
            fd,tmp=tempfile.mkstemp(prefix='release-',suffix='.tmp',dir=dst.parent)
            with os.fdopen(fd,'wb') as file:file.write(data)
            prepared.append((Path(tmp),dst))
        for tmp,dst in prepared:os.replace(tmp,dst)
    finally:
        for tmp,_ in prepared:
            if tmp.exists():tmp.unlink()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    default=os.environ.get('JAVA_HOME') or str(ROOT.parent/'build_tools/jdk_extracted/jdk-11.0.32.1+1')
    parser.add_argument('--jdk',type=Path,default=Path(default))
    parser.add_argument('--check-release',action='store_true')
    args=parser.parse_args()
    root=ROOT.resolve();jdk=args.jdk.resolve()
    if sys.platform!='win32':raise ReleaseError('Reference lock currently supports Windows x86_64 only')
    lock=load_lock(root)
    inventory=input_inventory(root)
    if args.check_release:
        existing=verify_release(root)
        source_commit=existing['source_commit']
    else:
        source_commit=head_commit(root)
        verify_source_commit(root,source_commit,inventory)
    jdk_identity=verify_jdk(jdk,lock)
    work=root/'build/verified';work.mkdir(parents=True,exist_ok=True)
    runroot=Path(tempfile.mkdtemp(prefix='repro-',dir=work))
    artifacts=[]
    # Different absolute paths; independent compiler and converter processes in each run.
    for index in (1,2):
        run=runroot/f'build-{index}';run.mkdir()
        artifacts.append(build_one(root,jdk,run,lock,inventory,str(index)))
    a,b=[p.read_bytes() for p in artifacts]
    if a!=b:raise ReleaseError('Independent builds differ; nothing published: '+str(runroot))
    # Detect edits to sources, scripts, dependencies or JDK made while tools were running.
    if input_inventory(root)!=inventory:raise ReleaseError('Inputs changed during build; nothing published')
    verify_source_commit(root,source_commit,inventory)
    if verify_jdk(jdk,lock)!=jdk_identity:raise ReleaseError('JDK changed during build')
    hashes=entry_hashes(a)
    manifest={'schema':2,'package_version':lock['package_version'],'target':lock['target'],
              'source_commit':source_commit,'cap_sha256':digest(a),**inventory,
              'jdk':jdk_identity,'canonicalization':lock['canonical_cap'],
              'cap_entries_sha256':hashes,'cap_components_sha256':{n:h for n,h in hashes.items() if n.endswith('.cap')},
              'verification':'Two independent builds; both raw and canonical CAPs passed Oracle off-card verifier',
              'text_hash_format':'SHA-256 of UTF-8 bytes with CRLF normalized to LF; dependencies/JDK/CAP use raw bytes',
              'binary_dependency_notice':lock['binary_dependency_notice']}
    record={'source_commit':source_commit,'mode':'check-release' if args.check_release else 'publish',
            'independent_builds':2,'cap_sha256':digest(a),'independent_artifacts_identical':True}
    if args.check_release:
        if a!=(root/'dist/SmartPGPApplet.cap').read_bytes():
            raise ReleaseError('Rebuilt CAP differs from published whole file; release unchanged')
        # Publication may not race verification.
        if verify_release(root)!=existing:raise ReleaseError('Release changed during check')
        print('PASS: two clean builds reproduce the entire published CAP, byte for byte.')
    else:
        publish(root,a,manifest)
        verify_release(root)
        print('Published byte-identical verified dist/prebuilt CAPs.')
    (runroot/'result.json').write_bytes(stable_json(record))
    (work/'last-result.json').write_bytes(stable_json(record))
    print('CAP SHA-256:',digest(a))
    print('Source/build-input commit:',source_commit)
    print('Local build logs:',runroot)

if __name__=='__main__':
    try:main()
    except (ReleaseError,OSError,ValueError,zipfile.BadZipFile) as e:raise SystemExit(str(e))
