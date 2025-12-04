# SBOM CLI Tool

## Description
CLI tool to ingest SPDX 3.0 JSON Software Bill of Materials (SBOMs) and query for components or licenses.  
This tool allows you to maintain a local database of SBOMs and quickly search for specific components or licenses across multiple documents.

# Ingest an SBOM
python cli.py ingest example-spdx.json

# Query by component
## Search for documents/packages containing a specific component:
python cli.py query --component openssl

# Filter by version (optional):
python cli.py query --component openssl --version 3.0.1

# Query by license
## Search for documents/packages containing a specific license:
python cli.py query --license Apache-2.0


 # Unit tests
 python -m unittest -v tests.test_db
