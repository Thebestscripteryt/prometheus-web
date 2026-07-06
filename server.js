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

function runObfuscation(sourceCode, preset) {
  return new Promise((resolve, reject) => {
    const args = ["prometheus-main.lua", "--preset", preset, "--out", "-", "-"];

    const child = execFile(
      LUA_BIN,
      args,
      { cwd: LUA_SRC_DIR, timeout: 30000, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          return reject(new Error(stderr || stdout || err.message));
        }
        if (!stdout) {
          return reject(new Error("Obfuscator did not produce output. " + stderr));
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
    res.status(500).json({ error: err.message || "Obfuscation failed." });
  }
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Prometheus web UI running on port ${PORT}`);
});
