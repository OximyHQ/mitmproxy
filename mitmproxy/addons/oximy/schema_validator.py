"""
JSON Schema validation for Oximy configs and output events.

Provides strict validation to ensure all configs conform to tool-config.schema.json
and all output events conform to trace-output.schema.json.

In dev mode, validation failures raise exceptions (fail-fast).
In prod mode, validation failures log warnings but continue (graceful degradation).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Try to import jsonschema, but make it optional
try:
    from jsonschema import Draft202012Validator

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    Draft202012Validator = None  # type: ignore
    logger.warning(
        "jsonschema not installed. Schema validation will be disabled. "
        "Install with: pip install jsonschema"
    )


@dataclass
class ValidationResult:
    """Result of schema validation."""

    valid: bool
    errors: list[str]

    @classmethod
    def success(cls) -> ValidationResult:
        return cls(valid=True, errors=[])

    @classmethod
    def failure(cls, errors: list[str]) -> ValidationResult:
        return cls(valid=False, errors=errors)


class SchemaValidator:
    """
    Validates JSON data against schemas.

    Supports both tool-config.schema.json and trace-output.schema.json.
    """

    # Schema cache
    _schemas: dict[str, dict] = {}
    _validators: dict[str, Any] = {}

    # Dev mode flag - set via environment variable or config
    _dev_mode: bool = os.environ.get("OXIMY_DEV_MODE", "").lower() in (
        "1",
        "true",
        "yes",
    )

    @classmethod
    def set_dev_mode(cls, enabled: bool) -> None:
        """Enable or disable dev mode (fail-fast on validation errors)."""
        cls._dev_mode = enabled

    @classmethod
    def is_available(cls) -> bool:
        """Check if schema validation is available (jsonschema installed)."""
        return JSONSCHEMA_AVAILABLE

    @classmethod
    def load_schema(cls, schema_path: Path | str) -> dict | None:
        """
        Load a JSON schema from file.

        Returns None if file doesn't exist or can't be parsed.
        """
        schema_path = Path(schema_path)
        cache_key = str(schema_path)

        if cache_key in cls._schemas:
            return cls._schemas[cache_key]

        if not schema_path.exists():
            logger.warning(f"Schema file not found: {schema_path}")
            return None

        try:
            with open(schema_path) as f:
                schema = json.load(f)
            cls._schemas[cache_key] = schema
            return schema
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to load schema {schema_path}: {e}")
            return None

    @classmethod
    def _get_validator(cls, schema_path: Path | str) -> Any | None:
        """Get or create a validator for a schema."""
        if not JSONSCHEMA_AVAILABLE:
            return None

        schema_path = Path(schema_path)
        cache_key = str(schema_path)

        if cache_key in cls._validators:
            return cls._validators[cache_key]

        schema = cls.load_schema(schema_path)
        if schema is None:
            return None

        if Draft202012Validator is not None:
            validator = Draft202012Validator(schema)
            cls._validators[cache_key] = validator
            return validator
        return None

    @classmethod
    def validate(
        cls,
        data: dict,
        schema_path: Path | str,
        context: str = "",
    ) -> ValidationResult:
        """
        Validate data against a JSON schema.

        Args:
            data: The data to validate
            schema_path: Path to the JSON schema file
            context: Optional context string for error messages (e.g., config file name)

        Returns:
            ValidationResult with valid=True if valid, or valid=False with error messages

        Raises:
            ValueError: In dev mode, if validation fails
        """
        if not JSONSCHEMA_AVAILABLE:
            # No validation available, assume valid
            return ValidationResult.success()

        validator = cls._get_validator(schema_path)
        if validator is None:
            # Schema couldn't be loaded, assume valid (with warning)
            logger.warning(f"Could not load schema {schema_path}, skipping validation")
            return ValidationResult.success()

        errors: list[str] = []
        for error in validator.iter_errors(data):
            path = ".".join(str(p) for p in error.path) or "(root)"
            prefix = f"{context}: " if context else ""
            errors.append(f"{prefix}{path}: {error.message}")

        if errors:
            result = ValidationResult.failure(errors)
            if cls._dev_mode:
                error_msg = "\n".join(errors)
                raise ValueError(f"Schema validation failed:\n{error_msg}")
            else:
                for error in errors:
                    logger.warning(f"Schema validation error: {error}")
            return result

        return ValidationResult.success()

    @classmethod
    def validate_tool_config(
        cls,
        config: dict,
        config_path: Path | str | None = None,
        schemas_dir: Path | str | None = None,
    ) -> ValidationResult:
        """
        Validate a tool config against tool-config.schema.json.

        Args:
            config: The config dict to validate
            config_path: Optional path for context in error messages
            schemas_dir: Optional path to schemas directory

        Returns:
            ValidationResult
        """
        if schemas_dir is None:
            # Default to registry/schemas relative to this file
            schemas_dir = Path(__file__).parent.parent.parent.parent / "registry" / "schemas"
        else:
            schemas_dir = Path(schemas_dir)

        schema_path = schemas_dir / "tool-config.schema.json"
        context = Path(config_path).name if config_path else ""

        return cls.validate(config, schema_path, context)

    @classmethod
    def validate_trace_output(
        cls,
        event: dict,
        event_id: str | None = None,
        schemas_dir: Path | str | None = None,
    ) -> ValidationResult:
        """
        Validate an output event against trace-output.schema.json.

        Args:
            event: The event dict to validate
            event_id: Optional event ID for context in error messages
            schemas_dir: Optional path to schemas directory

        Returns:
            ValidationResult
        """
        if schemas_dir is None:
            # Default to registry/schemas relative to this file
            schemas_dir = Path(__file__).parent.parent.parent.parent / "registry" / "schemas"
        else:
            schemas_dir = Path(schemas_dir)

        schema_path = schemas_dir / "trace-output.schema.json"
        context = f"event:{event_id}" if event_id else ""

        return cls.validate(event, schema_path, context)


def validate_config(config: dict, config_path: Path | str | None = None) -> ValidationResult:
    """Convenience function to validate a tool config."""
    return SchemaValidator.validate_tool_config(config, config_path)


def validate_event(event: dict, event_id: str | None = None) -> ValidationResult:
    """Convenience function to validate an output event."""
    return SchemaValidator.validate_trace_output(event, event_id)
