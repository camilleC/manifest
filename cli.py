import argparse
import json
import os
from db import init_db, insert_document, insert_package, query_by_component, query_by_license

# -----------------------------
# SPDX Parser (minimal)
# -----------------------------
def parse_spdx(sbom_json):
    """
    Parses an SPDX 3.0 JSON SBOM and returns a list of components/packages.
    Each component is a dict: {name, version, license}
    """
    components = []
    if "spdxVersion" not in sbom_json:
        raise ValueError("Not an SPDX 3.0 JSON SBOM")
    
    for pkg in sbom_json.get("packages", []):
        components.append({
            "name": pkg.get("name"),
            "version": pkg.get("versionInfo"),
            "license": pkg.get("licenseDeclared")
        })
    return components

# -----------------------------
# CLI Commands
# -----------------------------
def ingest_command(args):
    """Ingest SBOM file into database"""
    sbom_path = args.file
    if not os.path.exists(sbom_path):
        print(f"File not found: {sbom_path}")
        return

    with open(sbom_path, "r") as f:
        sbom_json = json.load(f)

    # Parse SPDX
    try:
        components = parse_spdx(sbom_json)
    except ValueError as e:
        print(f"Error parsing SBOM: {e}")
        return

    # Insert document
    document_id = insert_document(os.path.basename(sbom_path), json.dumps(sbom_json))
    print(f"Inserted document with ID {document_id}")

    # Insert packages
    for comp in components:
        insert_package(
            document_id,
            comp.get("name"),
            comp.get("version"),
            comp.get("license")
        )
    print(f"Inserted {len(components)} packages")

def query_command(args):
    """Query SBOMs by component or license"""
    if args.component:
        results = query_by_component(args.component, args.version)
        if results:
            for r in results:
                print(f"Document: {r[0]}, Component: {r[1]}, Version: {r[2]}, License: {r[3]}")
        else:
            print("No results found for component query.")
    elif args.license:
        results = query_by_license(args.license)
        if results:
            for r in results:
                print(f"Document: {r[0]}, Component: {r[1]}, Version: {r[2]}, License: {r[3]}")
        else:
            print("No results found for license query.")
    else:
        print("Please specify either --component or --license to query.")

# -----------------------------
# Main CLI
# -----------------------------
def main():
    # Initialize database
    init_db()

    parser = argparse.ArgumentParser(description="SBOM CLI Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Ingest command
    ingest_parser = subparsers.add_parser("ingest", help="Ingest an SBOM file")
    ingest_parser.add_argument("file", type=str, help="Path to SPDX JSON SBOM file")
    ingest_parser.set_defaults(func=ingest_command)

    # Query command
    query_parser = subparsers.add_parser("query", help="Query SBOMs")
    query_parser.add_argument("--component", type=str, help="Component/package name to search for")
    query_parser.add_argument("--version", type=str, help="Optional version to filter by")
    query_parser.add_argument("--license", type=str, help="License to search for")
    query_parser.set_defaults(func=query_command)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
