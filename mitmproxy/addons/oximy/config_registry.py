"""
Config registry for loading and indexing tool configurations.

Loads configs from the bundle and provides lookup methods for:
- Domain-based matching (websites)
- API domain matching (apps)
- Bundle ID / exe name matching (apps by signature)
"""

from __future__ import annotations

import fnmatch
import logging

logger = logging.getLogger(__name__)


class ConfigRegistry:
    """
    Registry for tool configurations.

    Loads configs from the bundle and provides efficient lookup.
    """

    def __init__(self):
        # Domain -> config (for websites)
        self._domain_index: dict[str, dict] = {}

        # API domain -> config (for apps with api_domains)
        self._api_domain_index: dict[str, dict] = {}

        # Bundle ID -> config (macOS apps)
        self._bundle_id_index: dict[str, dict] = {}

        # Exe name -> config (Windows apps)
        self._exe_name_index: dict[str, dict] = {}

        # All configs by ID
        self._configs: dict[str, dict] = {}

    def load_from_bundle(self, bundle: dict) -> None:
        """
        Load configs from a bundle dict.

        Args:
            bundle: The parsed bundle JSON with 'registry' key
        """
        registry = bundle.get("registry", {})

        # Load apps
        apps = registry.get("apps", {})
        for app_id, config in apps.items():
            self._load_config(app_id, config, "app")

        # Load websites
        websites = registry.get("websites", {})
        for website_id, config in websites.items():
            self._load_config(website_id, config, "website")

        logger.info(
            f"Loaded {len(apps)} apps and {len(websites)} websites into config registry"
        )
        logger.info(f"Domain index has {len(self._domain_index)} entries: {list(self._domain_index.keys())}")

    def _load_config(self, config_id: str, config: dict, source_type: str) -> None:
        """Load a single config and index it."""
        # Ensure config has required fields
        if "id" not in config:
            config["id"] = config_id

        self._configs[config_id] = config

        # Index by domains (websites)
        if source_type == "website":
            domains = config.get("domains", [])
            logger.debug(f"Indexing website {config_id} with domains: {domains}")
            for domain in domains:
                self._domain_index[domain.lower()] = config
                logger.debug(f"  Added domain index: {domain.lower()} -> {config_id}")

        # Index by api_domains (apps)
        for api_domain in config.get("api_domains", []):
            self._api_domain_index[api_domain.lower()] = config

        # Index by signatures (apps)
        signatures = config.get("signatures", {})

        # macOS bundle IDs
        macos_sig = signatures.get("macos", {})
        bundle_id = macos_sig.get("bundle_id")
        if bundle_id:
            self._bundle_id_index[bundle_id.lower()] = config

        # Windows exe names
        windows_sig = signatures.get("windows", {})
        exe_name = windows_sig.get("exe_name")
        if exe_name:
            self._exe_name_index[exe_name.lower()] = config

    def get_for_domain(self, domain: str) -> dict | None:
        """
        Get config for a website domain.

        Args:
            domain: Domain name (e.g., "chat.openai.com")

        Returns:
            Config dict or None if not found
        """
        domain = domain.lower()
        logger.debug(f"get_for_domain({domain}): domain_index has {len(self._domain_index)} entries")

        # Try exact match
        if domain in self._domain_index:
            logger.debug(f"get_for_domain({domain}): FOUND exact match")
            return self._domain_index[domain]

        # Try without www.
        if domain.startswith("www."):
            bare_domain = domain[4:]
            if bare_domain in self._domain_index:
                return self._domain_index[bare_domain]

        # Try with www.
        www_domain = f"www.{domain}"
        if www_domain in self._domain_index:
            return self._domain_index[www_domain]

        return None

    def get_for_api_domain(self, domain: str) -> dict | None:
        """
        Get config for an API domain.

        Args:
            domain: API domain (e.g., "api.anthropic.com")

        Returns:
            Config dict or None if not found
        """
        domain = domain.lower()
        return self._api_domain_index.get(domain)

    def get_for_bundle_id(self, bundle_id: str) -> dict | None:
        """
        Get config for a macOS bundle ID.

        Args:
            bundle_id: Bundle identifier (e.g., "com.anthropic.claudefordesktop")

        Returns:
            Config dict or None if not found
        """
        return self._bundle_id_index.get(bundle_id.lower())

    def get_for_exe_name(self, exe_name: str) -> dict | None:
        """
        Get config for a Windows executable name.

        Args:
            exe_name: Executable name (e.g., "cursor.exe")

        Returns:
            Config dict or None if not found
        """
        return self._exe_name_index.get(exe_name.lower())

    def get_config(self, config_id: str) -> dict | None:
        """Get a config by ID."""
        return self._configs.get(config_id)

    def get_all_configs(self) -> dict[str, dict]:
        """Get all configs."""
        return self._configs.copy()

    def match_url(
        self, url: str, config: dict, method: str | None = None
    ) -> tuple[str, dict] | None:
        """
        Match a URL against a config's features.

        Args:
            url: Request URL
            config: Tool config dict
            method: HTTP method (GET, POST, etc.) - optional

        Returns:
            (feature_key, endpoint_config) if matched, None otherwise
        """
        features = config.get("features", {})

        for feature_key, feature in features.items():
            endpoints = feature.get("endpoints", [])

            for endpoint in endpoints:
                match_config = endpoint.get("match", {})
                url_pattern = match_config.get("url")
                required_method = match_config.get("method")

                # Check URL pattern
                if not url_pattern or not self._url_matches(url, url_pattern):
                    continue

                # Check method if specified in config
                if required_method and method:
                    if required_method.upper() != method.upper():
                        continue

                return (feature_key, endpoint)

        return None

    def _url_matches(self, url: str, pattern: str) -> bool:
        """
        Check if a URL matches a glob pattern.

        Supports patterns like:
        - **/api/chat/* - Match any path containing /api/chat/
        - **/backend-api/f/conversation - Match exact path
        - https://api.example.com/* - Match specific domain
        """
        # Extract path from URL for matching
        from urllib.parse import urlparse

        parsed = urlparse(url)
        path = parsed.path

        # Handle ** prefix (match any domain)
        if pattern.startswith("**/"):
            path_pattern = pattern[3:]
            # Try with leading slash
            if fnmatch.fnmatch(path, "/" + path_pattern):
                return True
            # Try without leading slash
            if fnmatch.fnmatch(path, path_pattern):
                return True
            # Try path without leading slash against pattern
            if fnmatch.fnmatch(path.lstrip("/"), path_pattern):
                return True
            return False

        # Full URL pattern
        return fnmatch.fnmatch(url, pattern)

    def match_detection_source(
        self, url: str, config: dict, method: str | None = None
    ) -> dict | None:
        """
        Match a URL against a config's detection sources.

        Args:
            url: Request URL
            config: Tool config dict
            method: HTTP method (GET, POST, etc.) - optional

        Returns:
            Detection source config if matched, None otherwise
        """
        detection_sources = config.get("detection", [])

        for source in detection_sources:
            match_config = source.get("match", {})
            url_pattern = match_config.get("url")
            required_method = match_config.get("method")

            # Check URL pattern
            if not url_pattern or not self._url_matches(url, url_pattern):
                continue

            # Check method if specified in config
            if required_method and required_method != "*" and method:
                if required_method.upper() != method.upper():
                    continue

            return source

        return None

    def build_bundle_id_to_app_id_index(self) -> dict[str, str]:
        """
        Build a bundle_id/exe_name -> app_id index for process resolver.

        Returns:
            Dict mapping bundle_id or exe_name to config id
        """
        index: dict[str, str] = {}

        for config_id, config in self._configs.items():
            signatures = config.get("signatures", {})

            # macOS bundle ID
            macos_sig = signatures.get("macos", {})
            bundle_id = macos_sig.get("bundle_id")
            if bundle_id:
                index[bundle_id] = config_id

            # Windows exe name
            windows_sig = signatures.get("windows", {})
            exe_name = windows_sig.get("exe_name")
            if exe_name:
                index[exe_name] = config_id
                # Also add lowercase version
                index[exe_name.lower()] = config_id

        return index


# Global registry instance
_registry: ConfigRegistry | None = None


def get_registry() -> ConfigRegistry:
    """Get the global config registry instance."""
    global _registry
    if _registry is None:
        _registry = ConfigRegistry()
    return _registry


def load_registry_from_bundle(bundle: dict) -> ConfigRegistry:
    """Load the global registry from a bundle."""
    global _registry
    _registry = ConfigRegistry()
    _registry.load_from_bundle(bundle)
    return _registry
