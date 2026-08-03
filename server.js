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

// Heavier presets (Vmify in particular compiles the whole script into a
// custom bytecode VM) can legitimately take much longer than lighter
// presets, even for small inputs. Give each preset its own budget instead
// of a single one-size-fits-all timeout.
const PRESET_TIMEOUTS_MS = {
  Minify: 15000,
  Weak: 20000,
  Medium: 30000,
  Strong: 45000,
  Ultra: 90000,
};

const ANSI_PATTERN = /\x1b\[[0-9;]*m/g;

function extractCleanError(rawStderr, rawStdout, fallbackMessage, timedOut) {
  if (timedOut) {
    return "Obfuscation timed out before finishing. The selected preset (especially Ultra, which compiles your script into a custom bytecode VM) can take a while on larger scripts — try a lighter preset like Strong or Medium, or shorten the script.";
  }
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

  // Fall back to the first non-stack-trace looking line.
  const firstUseful = lines.find((l) => !l.startsWith("stack traceback") && !l.startsWith("[C]:") && !l.startsWith("./") && !/:\d+:\s*in function/.test(l));
  return firstUseful || lines[0] || "Obfuscation failed.";
}

function runObfuscation(sourceCode, preset) {
  return new Promise((resolve, reject) => {
    const args = ["prometheus-main.lua", "--preset", preset, "--out", "-", "-"];
    const timeoutMs = PRESET_TIMEOUTS_MS[preset] || 30000;

    const child = execFile(
      LUA_BIN,
      args,
      { cwd: LUA_SRC_DIR, timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          const timedOut = Boolean(err.killed || err.signal === "SIGTERM");
          return reject(new Error(extractCleanError(stderr, stdout, err.message, timedOut)));
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
