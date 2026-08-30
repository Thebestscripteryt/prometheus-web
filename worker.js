const VALID_PRESETS = new Set(["Minify", "Weak", "Medium", "Strong", "Ultra"]);

function corsHeaders(request, env) {
  const configured = env.ALLOWED_ORIGIN || "*";
  const requestOrigin = request.headers.get("Origin");
  const allowOrigin = configured === "*" ? "*" : (requestOrigin === configured ? configured : configured);
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function json(data, status, request, env, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...corsHeaders(request, env),
      ...extra,
    },
  });
}

async function handleObfuscate(request, env) {
  if (!env.ORIGIN_URL) {
    return json({ error: "API origin is not configured.", type: "configuration_error" }, 503, request, env);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Request body must be valid JSON.", type: "validation_error" }, 400, request, env);
  }

  const code = body?.code;
  const preset = body?.preset;
  if (typeof code !== "string" || !code.trim()) {
    return json({ error: "No script provided.", type: "validation_error" }, 400, request, env);
  }
  if (!VALID_PRESETS.has(preset)) {
    return json({ error: "Invalid preset.", type: "validation_error" }, 400, request, env);
  }

  const payload = JSON.stringify({ code, preset });

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("origin timeout"), 35_000);
  let originResponse;
  try {
    const target = new URL("/api/obfuscate", env.ORIGIN_URL).toString();
    originResponse = await fetch(target, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Forwarded-By": "prometheus-workers",
      },
      body: payload,
      signal: controller.signal,
    });
  } catch (error) {
    const message = error?.name === "AbortError" ? "Obfuscation service timed out." : "Obfuscation service is unavailable.";
    return json({ error: message, type: "upstream_error" }, 504, request, env);
  } finally {
    clearTimeout(timeout);
  }

  const raw = await originResponse.text();
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    data = { error: "Obfuscation service returned an invalid response.", type: "upstream_error" };
  }

  return json(data, originResponse.status, request, env, {
    "X-Request-Id": crypto.randomUUID(),
  });
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request, env) });

    const url = new URL(request.url);
    if (url.pathname === "/api/health" && request.method === "GET") {
      return json({ ok: true, edge: true, service: "prometheus" }, 200, request, env);
    }
    if (url.pathname === "/api/obfuscate" && request.method === "POST") {
      return handleObfuscate(request, env);
    }
    if (url.pathname.startsWith("/api/")) {
      return json({ error: "Not found." }, 404, request, env);
    }

    return env.ASSETS.fetch(request);
  },
};
