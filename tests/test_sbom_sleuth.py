import json, unittest
from sbom_sleuth import analyze_text

class SbomSleuthTests(unittest.TestCase):
    def test_cyclonedx_metadata_and_duplicate_findings(self):
        doc={"bomFormat":"CycloneDX","components":[{"name":"demo"},{"name":"demo"}]}
        report=analyze_text(json.dumps(doc)); rules={f["rule_id"] for f in report["findings"]}
        self.assertEqual(report["format"],"CycloneDX")
        for rule in ("SB001","SB002","SB003","SB004"): self.assertIn(rule,rules)
    def test_cyclonedx_unknown_dependency(self):
        doc={"bomFormat":"CycloneDX","components":[{"name":"a","version":"1","purl":"pkg:pypi/a@1","bom-ref":"a","licenses":[{"license":{"id":"MIT"}}]}],"dependencies":[{"ref":"a","dependsOn":["missing"]}]}
        report=analyze_text(json.dumps(doc))
        self.assertTrue(any(f["rule_id"]=="SB005" for f in report["findings"]))
    def test_spdx_document(self):
        doc={"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOC","packages":[{"name":"pkg","SPDXID":"SPDXRef-PKG"}],"relationships":[{"spdxElementId":"SPDXRef-DOC","relatedSpdxElement":"SPDXRef-PKG"}]}
        report=analyze_text(json.dumps(doc))
        self.assertEqual(report["format"],"SPDX"); self.assertEqual(report["component_count"],1)
        self.assertTrue(any(f["rule_id"]=="SB001" for f in report["findings"]))
    def test_rejects_invalid_and_unknown(self):
        with self.assertRaises(ValueError): analyze_text("{")
        with self.assertRaises(ValueError): analyze_text('{"name":"not sbom"}')
if __name__=="__main__": unittest.main()
