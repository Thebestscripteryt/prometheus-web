# Prometheus Web UI

A minimal web front-end for the Prometheus Lua/Luau obfuscator. Paste a script,
pick a preset, get obfuscated output — no CLI needed.

## Deploy on Render

1. Push this folder to a GitHub repo.
2. In Render: **New +** → **Web Service** → connect the repo.
3. Render should auto-detect `render.yaml` and build from the `Dockerfile`.
   If it doesn't, set manually in the service settings:
   - **Runtime:** Docker
   - **Dockerfile Path:** `./Dockerfile`
4. Deploy. First build takes a bit longer since it installs `lua5.1` via apt
   inside the Docker image.

> Note: Render's native "Node" runtime build environment does **not** allow
> `apt-get install` (it's a non-root, read-only filesystem outside the app
> dir), so a plain `Build Command: apt-get update && apt-get install -y
> lua5.1 && npm install` will fail with `Read-only file system`. Using the
> Docker runtime (as above) fixes this, since the Dockerfile's `RUN apt-get`
> step runs at image-build time with full root access.

## Run locally

```
npm install
sudo apt install lua5.1   # if not already installed
npm start
```

Then open `http://localhost:3000`.

## How it works

- `public/index.html` — the UI (paste script, pick preset, view output).
- `server.js` — Express server. On each request it writes the pasted script to
  a temp file, shells out to `lua5.1 prometheus-main.lua --preset X --out ...`,
  reads the result back, and deletes the temp files.
- `lua-src/` — the actual Prometheus obfuscator (Lua source), unchanged from
  the CLI version, extended for Luau (string interpolation, `+=`, `continue`).

## Notes

- Free Render instances spin down when idle — first request after a while
  will be slow (cold start + apt install already happened at build time, so
  this is just Node/process wake-up, not a full reinstall).
- Max script size is capped at 500KB in `server.js` — adjust `code.length`
  check there if you need more.
- There's no auth on `/api/obfuscate` — if you don't want this open to
  anyone who finds the URL, add a simple API key check or rate limiting
  before making it public.
