from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from testpulse.services import get_stream_snapshot

router = APIRouter(prefix='/runs', tags=['stream'])


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@router.get('/{run_id}/stream')
def stream_run(run_id: str, interval_ms: int = Query(default=2000, ge=500, le=10000), max_events: int | None = Query(default=None, ge=1, le=50)) -> StreamingResponse:
    async def event_generator():
        sent = 0
        try:
            current = get_stream_snapshot(run_id)
        except FileNotFoundError as exc:
            yield _sse('error', {'detail': str(exc)})
            return
        fingerprint = current.get('fingerprint')
        yield _sse('snapshot', current)
        sent += 1
        if max_events is not None and sent >= max_events:
            return
        while True:
            await asyncio.sleep(interval_ms / 1000)
            try:
                snapshot = get_stream_snapshot(run_id)
            except FileNotFoundError as exc:
                yield _sse('error', {'detail': str(exc)})
                return
            if snapshot.get('fingerprint') != fingerprint:
                fingerprint = snapshot.get('fingerprint')
                yield _sse('snapshot', snapshot)
                sent += 1
                if max_events is not None and sent >= max_events:
                    return
            else:
                yield ': keep-alive\n\n'
    return StreamingResponse(event_generator(), media_type='text/event-stream')
