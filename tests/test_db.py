import os
import json
import unittest
from db import init_db, insert_document, insert_package, query_by_component, query_by_license, get_connection

DB_FILE = "sbom.db"
TEST_SBOM_FILE = "tests/test-sbom.json"

# Make sure the test file exists
os.makedirs("tests", exist_ok=True)
with open(TEST_SBOM_FILE, "w") as f:
    json.dump({
        "spdxVersion": "SPDX-3.0",
        "packages": [
            {"name": "openssl", "versionInfo": "3.0.1", "licenseDeclared": "Apache-2.0"},
            {"name": "zlib", "versionInfo": "1.2.13", "licenseDeclared": "Zlib"}
        ]
    }, f, indent=2)


class TestSBOMDatabase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Initialize DB before any tests"""
        init_db()

    @classmethod
    def tearDownClass(cls):
        """Clean up DB and test file after all tests"""
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        if os.path.exists(TEST_SBOM_FILE):
            os.remove(TEST_SBOM_FILE)

    def insert_test_sbom(self):
        """Helper to insert test SPDX JSON and all packages"""
        with open(TEST_SBOM_FILE) as f:
            sbom_json = json.load(f)
        doc_id = insert_document("test-sbom.json", json.dumps(sbom_json))
        for pkg in sbom_json["packages"]:
            insert_package(doc_id, pkg["name"], pkg["versionInfo"], pkg["licenseDeclared"])
        return doc_id

    def test_insert_document_and_packages(self):
        """Test inserting document and its packages"""
        doc_id = self.insert_test_sbom()

        # Check document
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM documents WHERE id=?", (doc_id,))
        doc_rows = cur.fetchall()
        self.assertEqual(len(doc_rows), 1)
        self.assertEqual(doc_rows[0][1], "test-sbom.json")

        # Check packages
        cur.execute("SELECT * FROM packages WHERE document_id=?", (doc_id,))
        pkg_rows = cur.fetchall()
        self.assertEqual(len(pkg_rows), 2)
        package_names = {r[2] for r in pkg_rows}
        self.assertSetEqual(package_names, {"openssl", "zlib"})
        conn.close()

    def test_query_by_component(self):
        """Test querying by component"""
        self.insert_test_sbom()
        results = query_by_component("openssl")
        self.assertTrue(any(r[1] == "openssl" for r in results))

        results_with_version = query_by_component("openssl", version="3.0.1")
        self.assertTrue(any(r[1] == "openssl" and r[2] == "3.0.1" for r in results_with_version))

    def test_query_by_license(self):
        """Test querying by license"""
        self.insert_test_sbom()
        results = query_by_license("Apache-2.0")
        self.assertTrue(any(r[3] == "Apache-2.0" for r in results))


# No need for if __name__ == "__main__": when using python -m unittest
