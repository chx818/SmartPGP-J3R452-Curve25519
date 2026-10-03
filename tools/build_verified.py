"""Build from source and verify with Oracle tools; publish only after every step succeeds.
Extracting API classes avoids Windows JDK zipfs realpath failures. Does not edit SDKs.
"""
import argparse, hashlib, json, os, shutil, subprocess, sys, zipfile
if hasattr(sys.stdout,"reconfigure"): sys.stdout.reconfigure(encoding="utf-8")
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--jdk',type=Path,default=ROOT.parent/'build_tools/jdk_extracted/jdk-11.0.32.1+1');args=ap.parse_args()
    jdk=args.jdk.resolve();exe='.exe' if os.name=='nt' else ''
    work=ROOT/'build/verified';work.mkdir(parents=True,exist_ok=True)
    # Use a new workspace so stale classes can never enter a release.
    import tempfile
    run=Path(tempfile.mkdtemp(prefix='run-',dir=work))
    api=run/'api';api.mkdir();classes=run/'classes';classes.mkdir();out=run/'out';out.mkdir()
    for file in [ROOT/'sdks/jc305u3_kit/lib/api_classic.jar',ROOT/'lib/curve25519.jar']:
        with zipfile.ZipFile(file) as z:
            for n in z.namelist():
                if n.endswith(('.class','.exp')):
                    dest=(api/n).resolve()
                    if not dest.is_relative_to(api.resolve()):raise RuntimeError('unsafe archive path')
                    dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(z.read(n))
    kit=ROOT/'sdks/jc310r20210706_kit';exports=run/'exports';exports.mkdir()
    with zipfile.ZipFile(kit/'lib/tools.jar') as z:
        prefix='api_export_files_3.0.5/'
        for n in z.namelist():
            if n.startswith(prefix) and n.endswith('.exp'):
                dest=exports/n[len(prefix):];dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(z.read(n))
    log=[]
    def call(cmd):
        p=subprocess.run(list(map(str,cmd)),capture_output=True)
        output=(p.stdout+p.stderr).decode('utf-8',errors='replace');log.append(output)
        (work/'build.log').write_text('\n'.join(log),encoding='utf-8')
        print(output)
        if p.returncode:raise RuntimeError(f'tool failed: {cmd[0]}, exit={p.returncode}')
    call([jdk/'bin'/('javac'+exe),'-J-Duser.language=en','-J-Duser.country=US','-proc:none','-encoding','UTF-8','-source','7','-target','7','-g','-classpath',api,'-d',classes,*sorted((ROOT/'src').rglob('*.java'))])
    java=[jdk/'bin'/('java'+exe),'-Duser.language=en','-Duser.country=US','-cp',str(kit/'lib/*')]
    call(java+['com.sun.javacard.converter.Main','-target','3.0.5','-classdir',classes,'-exportpath',str(exports)+os.pathsep+str(api),'-applet','0xd2:0x76:0x00:0x01:0x24:0x01:0x03:0x04:0xaf:0xaf:0x00:0x00:0x00:0x00:0x00:0x00','fr.anssi.smartpgp.SmartPGPApplet','-d',out,'-out','CAP','EXP','fr.anssi.smartpgp','0xd2:0x76:0x00:0x01:0x24:0x01','1.1'])
    cap=out/'fr/anssi/smartpgp/javacard/smartpgp.cap'
    exp=list(exports.rglob('*.exp'))+list(api.rglob('*.exp'))
    call(java+['com.sun.javacard.offcardverifier.Verifier','-target','3.0.5',*exp,cap])
    for folder in ['dist','prebuilt']:
        (ROOT/folder).mkdir(exist_ok=True)
        shutil.copyfile(cap,ROOT/folder/'SmartPGPApplet.cap')
    manifest={'package_version':'1.1','target':'3.0.5','verification':'Oracle converter verification and standalone off-card verifier completed','cap_sha256':hashlib.sha256(cap.read_bytes()).hexdigest(),'source_sha256':{str(p.relative_to(ROOT)).replace('\\','/'):hashlib.sha256(p.read_bytes().replace(b'\r\n',b'\n')).hexdigest() for p in sorted((ROOT/'src').rglob('*.java'))},'dependencies':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ['lib/curve25519.jar','lib/Curve25519.cap','sdks/jc305u3_kit/lib/api_classic.jar','sdks/jc310r20210706_kit/lib/tools.jar']}}
    with zipfile.ZipFile(cap) as z:
        manifest['cap_components_sha256']={n:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.endswith('.cap')}
    manifest['text_hash_format']='SHA-256 over UTF-8 file bytes with CRLF normalized to LF; binary/dependency hashes use raw bytes'
    manifest['build_tools_sha256']={str(p.relative_to(ROOT)).replace('\\','/'):hashlib.sha256(p.read_bytes().replace(b'\r\n',b'\n')).hexdigest() for p in [ROOT/'tools/build_verified.py',ROOT/'build.xml']}
    (ROOT/'dist/build-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('Verified and published',manifest['cap_sha256'])
if __name__=='__main__':main()
