# TestPulse Run Viewer

The Run Viewer is the React Flow second surface for TestPulse.

## Current capabilities

- real run list from `GET /runs`
- run filtering by search, classification, and outcome
- timeline playback with step highlighting
- node-level detail drawer with status, recommendation, confidence, artifacts, and current playback step
- live refresh / polling
- real overlays from:
  - `GET /runs/{run_id}/timeline`
  - `GET /runs/{run_id}/health`
  - `GET /runs/{run_id}/artifacts`
  - `GET /runs/{run_id}/prognostics`

## Configure API base

Set `VITE_TESTPULSE_API_BASE` if the API is not running on `http://127.0.0.1:8000`.

## Development

```bash
npm install
npm run dev
```

## Production build

```bash
npm run build
```
