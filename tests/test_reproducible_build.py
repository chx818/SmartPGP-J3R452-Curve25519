"""Offline reproducibility/provenance tests; no card access or compiler download."""
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import release_support as r
import build_verified as builder


def archive(timestamp=(2026,10,3,12,0,0), creation=b'Sat Oct 03 12:00:00 HKT 2026', reverse=False, method=zipfile.ZIP_DEFLATED):
    data={'META-INF/MANIFEST.MF':b'Manifest-Version: 1.0\r\nJava-Card-CAP-Creation-Time: '+creation+b'\r\nKeep: unchanged\r\n',
          'pkg/javacard/Header.cap':bytes(range(16)), 'pkg/javacard/Method.cap':b'actual binary payload',
          'APPLET-INF/classes/Test.class':b'\xca\xfe\xba\xbe', 'APPLET-INF/applet.xml':b'<applet/>\n'}
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w') as z:
        z.comment=b'variable archive comment'
        for name in sorted(data,reverse=reverse):
            info=zipfile.ZipInfo(name,timestamp);info.extra=b'\xfe\xca\x00\x00';info.comment=b'entry-comment';info.compress_type=method
            z.writestr(info,data[name])
    return out.getvalue()

class CanonicalTests(unittest.TestCase):
    def test_different_times_order_compression_produce_identical_bytes(self):
        a=archive();b=archive((2025,1,1,0,0,0),b'Wed Jan 01 00:00:00 UTC 2025',True,zipfile.ZIP_STORED)
        self.assertNotEqual(a,b);self.assertEqual(r.canonical_cap(a),r.canonical_cap(b))
    def test_only_manifest_creation_attribute_changed(self):
        before=r.cap_entries(archive());after=r.cap_entries(r.canonical_cap(archive()))
        self.assertEqual(set(before),set(after))
        for name in before:
            if name!=r.MANIFEST_NAME:self.assertEqual(before[name],after[name])
        self.assertEqual(after[r.MANIFEST_NAME],r.normalized_manifest(before[r.MANIFEST_NAME]))
    def test_idempotent_and_fixed_zip_metadata(self):
        data=r.canonical_cap(archive());self.assertEqual(data,r.canonical_cap(data))
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            self.assertEqual(z.namelist(),sorted(z.namelist()));self.assertEqual(z.comment,b'')
            for i in z.infolist():
                self.assertEqual(i.date_time,r.FIXED_DATE);self.assertEqual(i.compress_type,zipfile.ZIP_STORED)
                self.assertEqual(i.extra,b'');self.assertEqual(i.comment,b'')
    def test_duplicate_zip_entries_rejected(self):
        out=io.BytesIO(archive())
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(out,'a') as z:z.writestr('pkg/javacard/Method.cap',b'override')
        with self.assertRaises(r.ReleaseError):r.canonical_cap(out.getvalue())
    def test_missing_or_duplicate_creation_time_rejected(self):
        with self.assertRaises(r.ReleaseError):r.normalized_manifest(b'Manifest-Version: 1.0\r\n')
        line=b'Java-Card-CAP-Creation-Time: arbitrary\r\n'
        with self.assertRaises(r.ReleaseError):r.normalized_manifest(line+line)
    def test_unsafe_archive_rejected(self):
        out=io.BytesIO(archive())
        with zipfile.ZipFile(out,'a') as z:z.writestr('../escape',b'bad')
        with self.assertRaises(r.ReleaseError):r.canonical_cap(out.getvalue())
    def test_binary_payload_mutation_changes_whole_hash(self):
        a=r.canonical_cap(archive());out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            for n,b in r.cap_entries(a).items():z.writestr(n,b+b'x' if n.endswith('Method.cap') else b)
        self.assertNotEqual(r.digest(a),r.digest(r.canonical_cap(out.getvalue())))
    def test_hidden_java_options_removed(self):
        with patch.dict(builder.os.environ,{'JAVA_TOOL_OPTIONS':'-javaagent:bad','_JAVA_OPTIONS':'bad','JDK_JAVA_OPTIONS':'bad','CLASSPATH':'bad','JDK_JAVAC_OPTIONS':'bad'}):env=builder.clean_environment()
        for key in ('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH','JDK_JAVAC_OPTIONS'):self.assertNotIn(key,env)
        self.assertEqual(env['TZ'],'UTC')
    def test_unsafe_input_path_rejected(self):
        for name in ('../secret','C:/secret','/tmp/x','x\\y','./x'):
            with self.assertRaises(r.ReleaseError):r.local_path(ROOT,name)

class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        def write(n,b):p=self.root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
        self.write=write
        for n in r.BUILD_INPUTS:write(n,b'# fixture\n')
        write('src/pkg/Test.java',b'package pkg;\nclass Test {}\n')
        deps={'lib/curve25519.jar':r.digest(b'interface'),'lib/Curve25519.cap':r.digest(b'wrapper'),'tool.jar':r.digest(b'tools')}
        write('lib/curve25519.jar',b'interface');write('lib/Curve25519.cap',b'wrapper');write('prebuilt/Curve25519.cap',b'wrapper');write('tool.jar',b'tools')
        self.lock={'schema':1,'target':'3.0.5','package_version':'1.1','jdk':{'vendor':'fixture','version':'11','files_sha256':{'release':r.digest(b'fixture JDK')}},
                   'dependencies_sha256':deps,'java_tool_classpath':['tool.jar'],
                   'canonical_cap':{'schema':1,'timestamp':list(r.FIXED_DATE),'manifest_creation_time':r.FIXED_CREATION.decode(),'compression':'ZIP_STORED','entry_order':'lexicographic'}}
        write(r.LOCK_PATH,r.stable_json(self.lock))
        self.git('init');self.git('add','.')
        self.git('-c','user.name=Offline Test','-c','user.email=offline@example.invalid','-c','commit.gpgsign=false','commit','-m','fixture source')
        self.commit=r.head_commit(self.root);self.inventory=r.input_inventory(self.root)
        self.cap=r.canonical_cap(archive());hashes=r.entry_hashes(self.cap)
        self.manifest={'schema':2,'source_commit':self.commit,'package_version':'1.1','target':'3.0.5',**self.inventory,
                       'jdk':self.lock['jdk'],'canonicalization':self.lock['canonical_cap'],'cap_sha256':r.digest(self.cap),
                       'cap_entries_sha256':hashes,'cap_components_sha256':{n:h for n,h in hashes.items() if n.endswith('.cap')}}
        builder.publish(self.root,self.cap,self.manifest)
    def tearDown(self):self.temp.cleanup()
    def git(self,*args):return r.git(self.root,*args)
    def test_good_release_integrity_and_committed_inputs(self):
        self.assertEqual(r.verify_release(self.root)['source_commit'],self.commit)
    def test_changed_source_rejected(self):
        self.write('src/pkg/Test.java',b'changed')
        with self.assertRaises(r.ReleaseError):r.verify_release(self.root)
    def test_untracked_extra_source_rejected(self):
        self.write('src/pkg/Extra.java',b'extra')
        with self.assertRaises(r.ReleaseError):r.verify_release(self.root)
    def test_source_line_endings_are_normalized(self):
        p=self.root/'src/pkg/Test.java';p.write_bytes(p.read_bytes().replace(b'\n',b'\r\n'))
        r.verify_release(self.root)
    def test_changed_dependency_rejected(self):
        self.write('tool.jar',b'changed')
        with self.assertRaises(r.ReleaseError):r.verify_release(self.root)
    def test_release_copy_mismatch_rejected(self):
        self.write('prebuilt/SmartPGPApplet.cap',self.cap+b'other')
        with self.assertRaises(r.ReleaseError):r.verify_release(self.root)
    def test_checksums_mismatch_rejected(self):
        self.write('dist/SHA256SUMS',b'wrong')
        with self.assertRaises(r.ReleaseError):r.verify_release(self.root)
    def test_manifest_cannot_bless_uncommitted_source(self):
        self.write('src/pkg/Test.java',b'changed source')
        self.manifest.update(r.input_inventory(self.root));builder.publish(self.root,self.cap,self.manifest)
        with self.assertRaises(r.ReleaseError):r.verify_release(self.root)
        r.verify_release(self.root,check_git=False) # explicitly weaker ZIP-source mode
    def test_missing_git_commit_rejected(self):
        self.manifest['source_commit']='0'*40;builder.publish(self.root,self.cap,self.manifest)
        with self.assertRaises(r.ReleaseError):r.verify_release(self.root)
    def test_noncanonical_container_rejected_even_with_updated_hashes(self):
        raw=archive();self.manifest['cap_sha256']=r.digest(raw);hashes=r.entry_hashes(raw)
        self.manifest['cap_entries_sha256']=hashes;self.manifest['cap_components_sha256']={n:h for n,h in hashes.items() if n.endswith('.cap')}
        builder.publish(self.root,raw,self.manifest)
        with self.assertRaises(r.ReleaseError):r.verify_release(self.root)
    def test_changed_jdk_is_rejected(self):
        jdk=self.root/'jdk';jdk.mkdir();(jdk/'release').write_bytes(b'fixture JDK');r.verify_jdk(jdk,self.lock)
        (jdk/'release').write_bytes(b'wrong')
        with self.assertRaises(r.ReleaseError):r.verify_jdk(jdk,self.lock)
    def test_extra_jdk_file_is_rejected(self):
        jdk=self.root/'jdk';jdk.mkdir();(jdk/'release').write_bytes(b'fixture JDK');(jdk/'extra.dll').write_bytes(b'bad')
        with self.assertRaises(r.ReleaseError):r.verify_jdk(jdk,self.lock)

if __name__=='__main__':unittest.main()
