from __future__ import annotations

from pathlib import Path
from typing import Any

from .pipeline import resolve_run_dir

TEXT_EXTENSIONS = {'.log', '.txt', '.json', '.md', '.csv', '.yaml', '.yml'}


def get_artifact_content(run_id: str, artifact_path: str, artifacts_dir: Path | None = None, max_chars: int = 12000) -> dict[str, Any]:
    run_dir = resolve_run_dir(run_id, artifacts_dir)
    safe_path = Path(artifact_path)
    candidate = (run_dir / safe_path).resolve()
    if run_dir.resolve() not in candidate.parents and candidate != run_dir.resolve():
        raise FileNotFoundError(f'Artifact not found: {artifact_path}')
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(f'Artifact not found: {artifact_path}')
    ext = candidate.suffix.lower()
    if ext not in TEXT_EXTENSIONS:
        return {
            'run_id': run_id,
            'artifact_path': artifact_path,
            'content_type': 'binary',
            'preview': f'Binary artifact ({ext or "unknown"}) cannot be previewed inline.',
            'download_path': f'/runs/{run_id}/artifacts/content?path={artifact_path}',
        }
    content = candidate.read_text(encoding='utf-8', errors='replace')
    if len(content) > max_chars:
        content = content[:max_chars] + '\n\n...[truncated]'
    return {
        'run_id': run_id,
        'artifact_path': artifact_path,
        'content_type': 'text',
        'preview': content,
        'download_path': f'/runs/{run_id}/artifacts/content?path={artifact_path}',
    }
