"""Install this SmartPGP applet only. No card-production configuration is read.
Uses GP's configured key environment. The shipped GP defaults apply if none is set.
Existing OpenPGP data is erased only with --replace-smartpgp.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'D27600012401'
INSTANCE = 'D276000124010304AFAF000000000000'
WRAPPER = 'FF00025519'

def verify_files(root=ROOT):
    manifest = json.loads((root/'dist/build-manifest.json').read_text(encoding='utf-8-sig'))
    for name in ('dist/SmartPGPApplet.cap', 'prebuilt/SmartPGPApplet.cap'):
        if hashlib.sha256((root/name).read_bytes()).hexdigest() != manifest['cap_sha256']:
            raise RuntimeError('CAP does not match verified build: '+name)
    for name, expected in manifest['source_sha256'].items():
        if hashlib.sha256((root/name).read_bytes().replace(b'\r\n', b'\n')).hexdigest() != expected:
            raise RuntimeError('Source changed since verified build: '+name)
    for name, expected in manifest['dependencies'].items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest() != expected:
            raise RuntimeError('Dependency changed since verified build: '+name)
    return manifest

def parse_registry(text):
    entries={};current=None
    for line in text.replace('\r','').splitlines():
        m=re.match(r'^(APP|PKG|ISD): ([0-9A-Fa-f]+) \(([^)]+)\)',line)
        if m:
            key=(m[1],m[2].upper())
            if key in entries: raise RuntimeError('Duplicate registry entry')
            current={'state':m[3]};entries[key]=current
        elif current is not None:
            m=re.match(r'^\s+(From|Version):\s+(\S+)',line)
            if m:current[m[1].lower()]=m[2].upper()
    if not any(k[0]=='ISD' for k in entries):raise RuntimeError('Incomplete GP registry; stopping')
    return entries

def installation_plan(entries, root, version, replace=False, strict=False):
    existing=[k[1] for k,v in entries.items() if k[0]=='APP' and v.get('from')==PACKAGE]
    if ('APP',INSTANCE) in entries and entries[('APP',INSTANCE)].get('from')!=PACKAGE:
        raise RuntimeError('Target AID belongs to another package')
    if (existing or ('PKG',PACKAGE) in entries) and not replace:
        raise RuntimeError('SmartPGP already present. --replace-smartpgp explicitly erases its keys/data.')
    wrapper=entries.get(('PKG',WRAPPER))
    if wrapper and (wrapper.get('version')!='1.0' or wrapper['state']!='LOADED'):
        raise RuntimeError('Unexpected Curve25519 package version/state; not replacing it')
    result=[]
    if not wrapper:result.append(['--load',str(root/'lib/Curve25519.cap')])
    result.extend(['--delete',aid] for aid in existing)
    if ('PKG',PACKAGE) in entries:result.append(['--delete',PACKAGE])
    result.append(['--install',str(root/'dist/SmartPGPApplet.cap'),'--params','01' if strict else '00'])
    return result

def redact(text):
    values=[v for k,v in os.environ.items() if k.upper().startswith('GP_KEY') and re.fullmatch(r'[0-9a-fA-F]{32,64}',v)]
    values.append('404142434445464748494A4B4C4D4E4F')
    for value in values:text=re.sub(re.escape(value),'[REDACTED]',text,flags=re.I)
    return text

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reader',default='PCD')
    parser.add_argument('--replace-smartpgp',action='store_true')
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--strict-contactless',action='store_true')
    group.add_argument('--contactless-plain',action='store_true',help='Compatibility alias; already the installer default')
    parser.add_argument('--report',type=Path,default=ROOT/'build/deployment.json')
    args=parser.parse_args(argv)
    if not args.reader.strip():parser.error('An explicit reader name/filter is required')
    manifest=verify_files()
    log=[]
    def run(options):
        result=subprocess.run([str(ROOT/'tools/gprun.bat'),'-r',args.reader,*options],capture_output=True)
        text=redact((result.stdout+result.stderr).decode('utf-8',errors='replace'))
        print(text,flush=True)
        log.append({'arguments':options,'exit':result.returncode,'output':text})
        if result.returncode:raise RuntimeError('GP failed; no automatic retry or continuation')
        return text
    complete=False
    try:
        before=parse_registry(run(['--list']))
        for options in installation_plan(before,ROOT,manifest['package_version'],args.replace_smartpgp,args.strict_contactless):run(options)
        after=parse_registry(run(['--list']))
        if after.get(('PKG',PACKAGE),{}).get('version')!=manifest['package_version']:
            raise RuntimeError('Installed package version mismatch')
        instance=after.get(('APP',INSTANCE),{})
        if instance.get('state')!='SELECTABLE' or instance.get('from')!=PACKAGE:
            raise RuntimeError('New applet not selectable or wrong package')
        for key,value in before.items():
            if key[0]=='APP' and value.get('from')!=PACKAGE and after.get(key)!=value:
                raise RuntimeError('Unexpected change to another applet registry entry')
        complete=True
    finally:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps({'completed':complete,'cap_sha256':manifest['cap_sha256'],
            'profile':'strict-contactless' if args.strict_contactless else 'contactless-plain','steps':log},indent=2),encoding='utf-8')

if __name__=='__main__':
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    main()
