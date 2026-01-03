#!/usr/bin/env python3
"""
Export OpenAPI specification from ReportMate FastAPI application.

Usage:
    python scripts/export_openapi.py

Output:
    Creates docs/api/openapi.json with the full OpenAPI 3.x specification
    
This should be run as part of the build/deploy pipeline to keep the
published API documentation in sync with the actual implementation.
"""

import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from main import app

def export_openapi():
    """Export OpenAPI schema to JSON file."""
    try:
        # Get OpenAPI schema from FastAPI
        openapi_schema = app.openapi()
        
        # Ensure output directory exists
        output_dir = Path(__file__).parent.parent / "docs" / "api"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = output_dir / "openapi.json"
        
        # Write formatted JSON
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(openapi_schema, f, indent=2, ensure_ascii=False)
        
        print(f"OpenAPI specification exported to: {output_path}")
        print(f"  Title: {openapi_schema.get('info', {}).get('title')}")
        print(f"  Version: {openapi_schema.get('info', {}).get('version')}")
        print(f"  Endpoints: {len(openapi_schema.get('paths', {}))}")
        
        # Count endpoints by tag
        tag_counts = {}
        for path, methods in openapi_schema.get('paths', {}).items():
            for method, details in methods.items():
                if method in ['get', 'post', 'put', 'patch', 'delete']:
                    for tag in details.get('tags', ['untagged']):
                        tag_counts[tag] = tag_counts.get(tag, 0) + 1
        
        print("  Endpoints by tag:")
        for tag, count in sorted(tag_counts.items()):
            print(f"    - {tag}: {count}")
            
    except ImportError as e:
        print(f"Error: Failed to import FastAPI app: {e}", file=sys.stderr)
        sys.exit(1)
    except (OSError, IOError) as e:
        print(f"Error: Failed to write OpenAPI spec: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: Unexpected error during OpenAPI export: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    export_openapi()
