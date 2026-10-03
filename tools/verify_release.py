"""Verify public CAP identity and committed build-input provenance. No card I/O."""
import argparse
from pathlib import Path
from release_support import ROOT, ReleaseError, verify_release

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--without-git',action='store_true',help='Weaker integrity-only check for source ZIPs; cannot establish source commit ownership')
    args=parser.parse_args()
    manifest=verify_release(args.root,check_git=not args.without_git)
    print('Whole CAP SHA-256:',manifest['cap_sha256'])
    print('Source/build-input commit:',manifest['source_commit'])
    print('dist/prebuilt identical; canonical container; all locked inputs verified.')
    print('Git provenance: '+('NOT CHECKED (source ZIP mode)' if args.without_git else 'verified against recorded commit'))
    print('Recompile independently: python tools/build_verified.py --jdk <locked-JDK> --check-release')

if __name__=='__main__':
    try:main()
    except (ReleaseError,OSError,ValueError) as e:raise SystemExit(str(e))
