"""Offline tests for the generic public SmartPGP installer. Never opens a card."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('installer',ROOT/'tools/deploy_verified.py')
i=importlib.util.module_from_spec(spec);spec.loader.exec_module(i)
BASE='''ISD: A000000151000000 (OP_READY)
APP: A000000001 (SELECTABLE)
     From: A000000002
PKG: FF00025519 (LOADED)
     Version: 1.0
'''
PGP='''APP: D276000124010304AFAF000000010000 (SELECTABLE)
     From: D27600012401
PKG: D27600012401 (LOADED)
     Version: 1.0
'''
class InstallerTests(unittest.TestCase):
    def test_fresh_install_uses_NFC(self):
        plan=i.installation_plan(i.parse_registry(BASE),ROOT,'1.1')
        self.assertEqual(len(plan),1);self.assertEqual(plan[0][-2:],['--params','00'])
    def test_strict_is_explicit(self):
        plan=i.installation_plan(i.parse_registry(BASE),ROOT,'1.1',strict=True)
        self.assertEqual(plan[-1][-2:],['--params','01'])
    def test_existing_card_requires_replacement_flag(self):
        with self.assertRaises(RuntimeError):i.installation_plan(i.parse_registry(BASE+PGP),ROOT,'1.1')
    def test_replacement_only_deletes_openpgp(self):
        plan=i.installation_plan(i.parse_registry(BASE+PGP),ROOT,'1.1',replace=True)
        self.assertEqual(plan[0],['--delete','D276000124010304AFAF000000010000'])
        self.assertEqual(plan[1],['--delete',i.PACKAGE])
        self.assertNotIn('A000000001',str(plan))
    def test_missing_wrapper_loaded_first(self):
        plan=i.installation_plan(i.parse_registry('ISD: A000000151000000 (OP_READY)\n'),ROOT,'1.1')
        self.assertEqual(plan[0][0],'--load');self.assertEqual(plan[1][0],'--install')
    def test_unknown_wrapper_version_rejected(self):
        with self.assertRaises(RuntimeError):i.installation_plan(i.parse_registry(BASE.replace('Version: 1.0','Version: 2.0')),ROOT,'1.1')
    def test_registry_failure_is_not_empty_card(self):
        with self.assertRaises(RuntimeError):i.parse_registry('connection failed')
    def test_foreign_AID_collision_rejected(self):
        text=BASE+f'APP: {i.INSTANCE} (SELECTABLE)\n     From: A000000002\n'
        with self.assertRaises(RuntimeError):i.installation_plan(i.parse_registry(text),ROOT,'1.1',replace=True)
    def test_current_CAP_and_sources_verified_offline(self):
        self.assertEqual(i.verify_files(ROOT)['package_version'],'1.1')

if __name__=='__main__':unittest.main()
