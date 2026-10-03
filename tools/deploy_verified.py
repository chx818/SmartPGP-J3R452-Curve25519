"""Replace ONLY SmartPGP on an explicitly selected reader after checking build hashes.
Default profile requires SM for contactless sensitive commands. --contactless-plain
is an explicit compatibility exception. Uses default GP keys only if GP is not configured.
"""
import argparse,hashlib,json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--reader',required=True);p.add_argument('--replace-smartpgp',action='store_true');p.add_argument('--contactless-plain',action='store_true');args=p.parse_args()
 if not args.replace_smartpgp:p.error('--replace-smartpgp is required: existing OpenPGP keys will be erased')
 m=json.loads((ROOT/'dist/build-manifest.json').read_text());cap=ROOT/'dist/SmartPGPApplet.cap'
 def digest(file):return hashlib.sha256(file.read_bytes()).hexdigest()
 if digest(cap)!=m['cap_sha256']:raise RuntimeError('CAP does not match verified build')
 for n,h in m['source_sha256'].items():
  if hashlib.sha256((ROOT/n).read_bytes().replace(b'\r\n',b'\n')).hexdigest()!=h:raise RuntimeError('Source changed since verified build: '+n)
 for n,h in m['dependencies'].items():
  if digest(ROOT/n)!=h:raise RuntimeError('Dependency changed: '+n)
 runner=ROOT/'tools/gprun.bat';log=[]
 def run(*argv):
  cmd=[str(runner),'-r',args.reader,*map(str,argv)]
  result=subprocess.run(cmd,capture_output=True)
  text=(result.stdout+result.stderr).decode('utf-8',errors='replace');print(text,flush=True)
  # Public test management key must not appear in archived logs.
  text=re.sub(r'404142434445464748494A4B4C4D4E4F','[default test GP key]',text,flags=re.I)
  log.append({'args':list(map(str,argv)),'exit':result.returncode,'output':text})
  if result.returncode:raise RuntimeError('GP command failed; stopped without touching other applications')
  return text
 report=ROOT/'reports/2026-10-03/deployment.json';report.parent.mkdir(exist_ok=True,parents=True)
 try:
  before=run('--list');apps=re.findall(r'^APP: ([0-9A-F]+)',before,re.M)
  if 'PKG: FF00025519 ' not in before:raise RuntimeError('Required wrapper is missing; provision trusted wrapper explicitly')
  targets=[]
  for match in re.finditer(r'^APP: ([0-9A-F]+)[^\n]*\n((?:[ \t]+[^\n]*\n)*)',before.replace('\r',''),re.M):
   origin=re.search(r'^\s+From:\s+([0-9A-F]+)',match.group(2),re.M)
   if origin and origin.group(1)=='D27600012401':targets.append(match.group(1))
  for aid in targets:run('--delete',aid)
  if 'PKG: D27600012401 ' in before:run('--delete','D27600012401')
  run('--install',cap,'--params','00' if args.contactless_plain else '01')
  after=run('--list');remaining=set(re.findall(r'^APP: ([0-9A-F]+)',after,re.M))
  if not set(apps).difference(targets).issubset(remaining):raise RuntimeError('Unexpected registry difference')
  if 'APP: D276000124010304AFAF000000000000 ' not in after:raise RuntimeError('New applet missing')
 finally:
  report.write_text(json.dumps({'cap_sha256':m['cap_sha256'],'profile':'contactless-plain' if args.contactless_plain else 'strict-contactless','steps':log},indent=2),encoding='utf-8')
if __name__=='__main__':main()
