const express = require("express");
const multer = require("multer");
const { execFile } = require("child_process");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const LUA_SRC_DIR = path.join(__dirname, "lua-src");
const LOCAL_LUA_BIN = path.join(__dirname, "vendor", "bin", "lua5.1");
const LUA_BIN = fs.existsSync(LOCAL_LUA_BIN) ? LOCAL_LUA_BIN : "lua5.1";

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });

const VALID_PRESETS = ["Minify", "Weak", "Medium", "Strong", "Ultra"];

const ANSI_PATTERN = /\x1b\[[0-9;]*m/g;

function extractCleanError(rawStderr, rawStdout, fallbackMessage) {
  const raw = (rawStderr || rawStdout || fallbackMessage || "Obfuscation failed.").toString();
  const clean = raw.replace(ANSI_PATTERN, "");

  // Prometheus prints its own diagnostic lines like:
  //   PROMETHEUS: Parsing Error at Position 3:5, unexpected token ...
  // Prefer that over the generic Lua interpreter wrapper + stack traceback that follows it.
  // Search from the end, since the actual error is logged right before the process dies -
  // earlier PROMETHEUS: lines are just progress messages ("Parsing ...", "Applying Step ...").
  const lines = clean.split("\n").map((l) => l.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    if (lines[i].startsWith("PROMETHEUS:") && /error/i.test(lines[i])) {
      return lines[i].replace(/^PROMETHEUS:\s*/, "");
    }
  }

  // Fall back to the last non-stack-trace looking line - the real crash
  // message (whether or not it happens to be PROMETHEUS-prefixed, and
  // whether or not it contains the word "error") is printed right before
  // the stack traceback begins, not at the start of the output. Searching
  // from the start would instead grab an early, harmless progress message
  // like "PROMETHEUS: Applying Obfuscation Pipeline to ...".
  const isTraceLine = (l) =>
    l.startsWith("stack traceback") || l.startsWith("[C]:") || l.startsWith("./") || /:\d+:\s*in function/.test(l);
  for (let i = lines.length - 1; i >= 0; i--) {
    if (!isTraceLine(lines[i])) {
      return lines[i];
    }
  }
  return lines[0] || "Obfuscation failed.";
}

function runObfuscation(sourceCode, preset) {
  return new Promise((resolve, reject) => {
    const args = ["prometheus-main.lua", "--preset", preset, "--out", "-", "-"];

    const child = execFile(
      LUA_BIN,
      args,
      { cwd: LUA_SRC_DIR, timeout: 30000, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          return reject(new Error(extractCleanError(stderr, stdout, err.message)));
        }
        if (!stdout) {
          return reject(new Error(extractCleanError(stderr, stdout, "Obfuscator did not produce output.")));
        }
        resolve(stdout);
      }
    );

    child.stdin.on("error", () => {}); // avoid unhandled EPIPE if the process exits early on bad input
    child.stdin.write(sourceCode);
    child.stdin.end();
  });
}

app.post("/api/obfuscate", upload.none(), async (req, res) => {
  try {
    const { code, preset } = req.body;

    if (!code || typeof code !== "string" || !code.trim()) {
      return res.status(400).json({ error: "No script provided." });
    }
    if (code.length > 500000) {
      return res.status(400).json({ error: "Script is too large (max 500KB)." });
    }
    if (!VALID_PRESETS.includes(preset)) {
      return res.status(400).json({ error: "Invalid preset." });
    }

    const result = await runObfuscation(code, preset);
    res.json({ output: result });
  } catch (err) {
    const message = err.message || "Obfuscation failed.";
    const type = /Parsing Error/i.test(message) ? "syntax_error" : "obfuscation_error";
    res.status(400).json({ error: message, type });
  }
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Prometheus web UI running on port ${PORT}`);
});
