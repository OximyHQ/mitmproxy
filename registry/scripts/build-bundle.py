#!/usr/bin/env python3
"""
Build OISP Spec Bundle

Creates a single JSON bundle from the generated models.json that sensors can fetch
at runtime. This enables dynamic provider/model updates without recompiling.

The bundle includes (all from sync-models.py generated data):
1. Provider registry with api_format for each provider
2. Model registry with pricing, capabilities, families
3. Parsers for each API format (openai, anthropic, google, bedrock, cohere)
4. Domain lookup table for provider detection
5. Domain patterns for wildcard matching (Azure, Bedrock)
6. App and website configs (validated against tool-config.schema.json)

Output: dist/oximy-bundle.json

Usage:
    python scripts/build-bundle.py
    python scripts/build-bundle.py --output ./custom-path.json
    python scripts/build-bundle.py --skip-validation  # Skip schema validation
"""

import argparse
import json
import sys
from datetime import datetime
from datetime import timezone
from pathlib import Path

try:
    import jsonschema
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    print("Warning: jsonschema not installed. Run 'pip install jsonschema' for config validation.", file=sys.stderr)

REGISTRY_ROOT = Path(__file__).parent.parent
PROVIDERS_DIR = REGISTRY_ROOT / "providers"
REGISTRY_DIR = REGISTRY_ROOT
SCHEMAS_DIR = REGISTRY_ROOT / "schemas"


def load_json(path: Path) -> dict:
    """Load a JSON file."""
    with open(path) as f:
        return json.load(f)


def load_schema(schema_name: str) -> dict | None:
    """Load a JSON schema file."""
    schema_path = SCHEMAS_DIR / schema_name
    if not schema_path.exists():
        print(f"Warning: Schema {schema_path} not found.", file=sys.stderr)
        return None
    return load_json(schema_path)


def validate_config(config: dict, schema: dict, config_path: Path) -> list[str]:
    """
    Validate a config against a JSON schema.

    Returns list of error messages (empty if valid).
    """
    if not JSONSCHEMA_AVAILABLE or schema is None:
        return []

    errors = []
    validator = jsonschema.Draft202012Validator(schema)
    for error in validator.iter_errors(config):
        path = ".".join(str(p) for p in error.path) or "(root)"
        errors.append(f"{config_path.name}: {path}: {error.message}")
    return errors


def load_registry_from_folder(
    folder_path: Path,
    schema: dict | None = None,
    validate: bool = True,
) -> tuple[str, dict, list[str]]:
    """
    Load registry items from a folder structure.

    Structure:
        folder_path/
            _meta.json          # Optional, contains version
            <category>/
                <id>.json       # Individual item files

    Args:
        folder_path: Path to the registry folder
        schema: JSON schema to validate against (optional)
        validate: Whether to validate configs (default True)

    Returns:
        (version, items_dict, errors_list)
    """
    version = "1.0.0"
    items = {}
    all_errors = []

    if not folder_path.exists():
        return version, items, all_errors

    # Load version from _meta.json if exists
    meta_path = folder_path / "_meta.json"
    if meta_path.exists():
        meta = load_json(meta_path)
        version = meta.get("version", version)

    # Load all JSON files from category subdirectories
    for category_dir in folder_path.iterdir():
        if not category_dir.is_dir() or category_dir.name.startswith("_"):
            continue

        for item_file in category_dir.glob("*.json"):
            item_id = item_file.stem  # filename without .json
            try:
                item_data = load_json(item_file)

                # Validate against schema if provided
                if validate and schema:
                    errors = validate_config(item_data, schema, item_file)
                    if errors:
                        all_errors.extend(errors)

                items[item_id] = item_data
            except Exception as e:
                all_errors.append(f"{item_file}: Failed to load: {e}")

    return version, items, all_errors


def load_registry(validate: bool = True) -> tuple[dict, list[str]]:
    """
    Load app and website registries from folder structure.

    Args:
        validate: Whether to validate configs against schema

    Returns:
        (registry_dict, errors_list)
    """
    result = {"version": "1.0.0", "apps": {}, "websites": {}}
    all_errors = []

    # Load schema for validation
    schema = load_schema("tool-config.schema.json") if validate else None

    # Load apps from apps/ folder
    apps_version, apps, app_errors = load_registry_from_folder(
        REGISTRY_DIR / "apps", schema=schema, validate=validate
    )
    result["version"] = apps_version
    result["apps"] = apps
    all_errors.extend(app_errors)

    # Load websites from websites/ folder
    _, websites, website_errors = load_registry_from_folder(
        REGISTRY_DIR / "websites", schema=schema, validate=validate
    )
    result["websites"] = websites
    all_errors.extend(website_errors)

    return result, all_errors


def load_models() -> dict:
    """Load the generated models registry (source of truth)."""
    models_path = PROVIDERS_DIR / "_generated" / "models.json"
    if not models_path.exists():
        print(
            f"Error: {models_path} not found. Run sync-models.py first.",
            file=sys.stderr,
        )
        sys.exit(1)
    return load_json(models_path)


def build_bundle(validate: bool = True) -> tuple[dict, list[str]]:
    """
    Build the complete spec bundle from generated models.json.

    Args:
        validate: Whether to validate configs against schema

    Returns:
        (bundle_dict, errors_list)
    """
    models_data = load_models()
    registry_data, validation_errors = load_registry(validate=validate)

    bundle = {
        "$schema": "https://oisp.dev/schema/v0.1/bundle.schema.json",
        "version": models_data.get("version", "0.1"),
        "bundle_version": "2.2.0",  # New format with pipeline-based configs
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "oisp-spec",
        "source_url": models_data.get("source_url", "https://models.dev/api.json"),
        "logos_url": models_data.get("logos_url", "https://models.dev/logos"),
        # Stats
        "stats": models_data.get("stats", {}),
        # Provider registry with api_format
        "providers": models_data.get("providers", {}),
        # Domain lookup for provider detection
        "domain_lookup": models_data.get("domain_lookup", {}),
        # Domain patterns for wildcard matching (Azure, Bedrock)
        "domain_patterns": models_data.get("domain_patterns", []),
        # Parsers for each API format
        "parsers": models_data.get("parsers", {}),
        # Model registry
        "models": models_data.get("models", {}),
        # App and website registry
        "registry": {
            "version": registry_data.get("version", "1.0.0"),
            "apps": registry_data.get("apps", {}),
            "websites": registry_data.get("websites", {}),
            "icons_url": "https://oisp.dev/registry/icons",
        },
    }

    return bundle, validation_errors


def main():
    parser = argparse.ArgumentParser(description="Build OISP Spec Bundle")
    parser.add_argument(
        "--output",
        type=Path,
        default=REGISTRY_ROOT / "dist" / "oximy-bundle.json",
        help="Output path for bundle",
    )
    parser.add_argument("--minify", action="store_true", help="Minify JSON output")
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip schema validation of configs",
    )
    args = parser.parse_args()

    # Build bundle
    print("Building OISP Spec Bundle...")
    validate = not args.skip_validation
    bundle, validation_errors = build_bundle(validate=validate)

    # Report validation errors
    if validation_errors:
        print("\n" + "=" * 60, file=sys.stderr)
        print("VALIDATION ERRORS:", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        for error in validation_errors:
            print(f"  ERROR: {error}", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"\n{len(validation_errors)} validation error(s) found.", file=sys.stderr)
        print("Fix the errors above or use --skip-validation to proceed anyway.", file=sys.stderr)
        sys.exit(1)
    elif validate and JSONSCHEMA_AVAILABLE:
        print("All configs validated successfully against tool-config.schema.json")

    # Create output directory
    args.output.parent.mkdir(parents=True, exist_ok=True)

    # Write bundle
    indent = None if args.minify else 2
    with open(args.output, "w") as f:
        json.dump(bundle, f, indent=indent, sort_keys=True)

    # Print stats
    stats = bundle.get("stats", {})
    registry = bundle.get("registry", {})
    print(f"\nBundle written to: {args.output}")
    print(f"  Version: {bundle['bundle_version']}")
    print(f"  Providers: {stats.get('providers', len(bundle['providers']))}")
    print(f"  Models: {stats.get('total_models', len(bundle['models']))}")
    print(f"  API Formats: {stats.get('api_formats', len(bundle['parsers']))}")
    print(f"  Domains indexed: {len(bundle['domain_lookup'])}")
    print(f"  Domain patterns: {len(bundle['domain_patterns'])}")
    print(f"  Parsers: {', '.join(bundle['parsers'].keys())}")
    print(f"  Apps: {len(registry.get('apps', {}))}")
    print(f"  Websites: {len(registry.get('websites', {}))}")

    # Also write a minified version
    if not args.minify:
        min_path = args.output.with_suffix(".min.json")
        with open(min_path, "w") as f:
            json.dump(bundle, f, separators=(",", ":"), sort_keys=True)
        print(f"  Minified: {min_path}")


if __name__ == "__main__":
    main()
