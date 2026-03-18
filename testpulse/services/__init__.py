"""Shared service layer for CLI, MCP, and web/API clients.

Keep imports lazy so core modules can depend on individual service modules
without triggering orchestration import cycles.
"""

from pathlib import Path
from typing import Any


def analyze_run(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .pipeline import analyze_run as _impl
    return _impl(*args, **kwargs)


def resolve_run_dir(*args: Any, **kwargs: Any) -> Path:
    from .pipeline import resolve_run_dir as _impl
    return _impl(*args, **kwargs)


def load_bundle_from_dir(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .pipeline import load_bundle_from_dir as _impl
    return _impl(*args, **kwargs)


def load_json_if_exists(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .pipeline import load_json_if_exists as _impl
    return _impl(*args, **kwargs)


def get_timeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .timeline_service import get_timeline as _impl
    return _impl(*args, **kwargs)


def get_component_health(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .diagnostics_service import get_component_health as _impl
    return _impl(*args, **kwargs)


def get_bundle(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .diagnostics_service import get_bundle as _impl
    return _impl(*args, **kwargs)


def get_artifact_map(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .diagnostics_service import get_artifact_map as _impl
    return _impl(*args, **kwargs)


def get_prognostics(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .prognostics_service import get_prognostics as _impl
    return _impl(*args, **kwargs)


def list_history(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
    from .history_service import list_history as _impl
    return _impl(*args, **kwargs)


def get_prognostic_trends(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .trend_service import get_prognostic_trends as _impl
    return _impl(*args, **kwargs)


def get_artifact_content(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .artifact_content_service import get_artifact_content as _impl
    return _impl(*args, **kwargs)


def load_historical_bundle(*args: Any, **kwargs: Any) -> dict[str, Any] | None:
    from .history_service import load_historical_bundle as _impl
    return _impl(*args, **kwargs)


def get_recommendation_rollup(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .comparison_service import get_recommendation_rollup as _impl
    return _impl(*args, **kwargs)


def get_artifact_diff(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .comparison_service import get_artifact_diff as _impl
    return _impl(*args, **kwargs)


def get_stream_snapshot(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .comparison_service import get_stream_snapshot as _impl
    return _impl(*args, **kwargs)


__all__ = [
    'analyze_run',
    'resolve_run_dir',
    'load_bundle_from_dir',
    'load_json_if_exists',
    'get_timeline',
    'get_component_health',
    'get_bundle',
    'get_artifact_map',
    'get_prognostics',
    'list_history',
    'get_prognostic_trends',
    'get_artifact_content',
    'load_historical_bundle',
    'get_recommendation_rollup',
    'get_artifact_diff',
    'get_stream_snapshot',
]
