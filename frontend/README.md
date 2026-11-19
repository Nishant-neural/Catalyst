# pyreach frontend

React + Vite interface for the PyReach vulnerability-reachability scanner.
It shows scan results in the browser — verdict, call path, execution
witness, uncertain explainer, OpenVEX, and the concede-or-cite debate —
instead of reading `report.json` by hand. The deterministic scanner stays
the source of truth; this UI only displays what the API returns.

## Run it

From the repository root, start the backend first:

```powershell
python -m pip install -e ".[api]"
uvicorn pyreach.api:app --reload --host 127.0.0.1 --port 8000
```

Then, in a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL printed in the terminal (normally
`http://localhost:5173`). The API client defaults to
`http://localhost:8000`; set `VITE_API_URL` in `frontend/.env` only if the
backend runs at a different address (`frontend/.env.example` shows the
default).

## What the UI does

- **Scan tab**: pick a fixture or type a project path, optionally give a
  live package + pinned version and/or an advisory JSON, then run the scan.
  `DEPENDENCY SOURCE (--with-deps)` parses the advisory package's own
  source from PyPI — that is what lets a SafeLoader-only call prove
  `not_reachable` (needs a pinned package + version). `UNCERTAIN EXPLAINER
  (--explain)` explains every uncertain result with its blocker and the
  discriminating check. `LOAD REPORT.JSON` opens a report made by the CLI
  without running a scan.
- **Verify tab**: runs every offline fixture in `verify.py` against the
  deterministic core and shows pass/fail per fixture. Click a row to open
  that fixture in the Scan tab.

## API used (`pyreach/api.py`)

- `GET /api/health`, `GET /api/fixtures`
- `POST /api/scan` — runs the CLI with `--explain` and `--with-deps` on by
  default; the response is the CLI report plus `openvex` (read from the
  VEX file the CLI writes, so the OpenVEX badge and copy button work).
- `POST /api/debate` — concede-or-cite challenge against a verdict.
- `POST /api/verify` — the fixture matrix above.

Only scan projects you trust: the execution witness runs project code in
a subprocess and is not a sandbox. Keep API keys in the repository `.env`
file; never put them in frontend code or commit them.
