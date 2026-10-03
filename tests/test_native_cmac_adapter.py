"""Functional sequencing tests for the production native-CMAC adapter, not a native/SCA simulator."""
import os
from pathlib import Path
import unittest
from native_cmac_host import ROOT,java_checks

class NativeAdapterTests(unittest.TestCase):
    def test_actual_adapter_vectors_and_failures(self):
        jdk=Path(os.environ.get('JAVA_HOME',''))
        if not (jdk/'bin/javac.exe').exists():jdk=ROOT.parent/'build_tools/jdk_extracted/jdk-11.0.32.1+1'
        self.assertTrue((jdk/'bin/javac.exe').exists(),'JDK required')
        lines=java_checks(jdk)
        self.assertTrue(any('772 split/truncation cases' in line for line in lines))
        print('\n'.join(lines))

if __name__=='__main__':unittest.main()
