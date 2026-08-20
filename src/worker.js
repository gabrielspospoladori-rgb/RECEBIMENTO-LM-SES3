var encoder = new TextEncoder();
var MAX_BODY_BYTES = 2 * 1024 * 1024;
var SESSION_DURATION_MS = 12 * 60 * 60 * 1000;
var ALLOWED_ORIGINS = [
  "https://gabrielspospoladori-rgb.github.io",
  "http://127.0.0.1",
  "http://localhost"
];

function allowedOrigin(request) {
  var origin = request.headers.get("Origin") || "";
  if (!origin) return "";
  for (var i = 0; i < ALLOWED_ORIGINS.length; i++) {
    if (origin === ALLOWED_ORIGINS[i] || origin.indexOf(ALLOWED_ORIGINS[i] + ":") === 0) return origin;
  }
  return "";
}

function corsHeaders(request) {
  var origin = allowedOrigin(request);
  var headers = {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "Vary": "Origin"
  };
  if (origin) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type";
    headers["Access-Control-Allow-Methods"] = "GET, PUT, POST, OPTIONS";
    headers["Access-Control-Max-Age"] = "86400";
  }
  return headers;
}

function jsonResponse(request, body, status) {
  return new Response(JSON.stringify(body), { status: status || 200, headers: corsHeaders(request) });
}

function bytesToBase64Url(bytes) {
  var binary = "";
  for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  var base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  var binary = atob(base64);
  var bytes = new Uint8Array(binary.length);
  for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function createSessionToken(secret) {
  var payload = bytesToBase64Url(encoder.encode(JSON.stringify({
    exp: Date.now() + SESSION_DURATION_MS,
    nonce: crypto.randomUUID()
  })));
  var key = await hmacKey(secret);
  var signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(payload)));
  return payload + "." + bytesToBase64Url(signature);
}

async function verifySessionToken(token, secret) {
  var parts = String(token || "").split(".");
  if (parts.length !== 2) return false;
  try {
    var key = await hmacKey(secret);
    var valid = await crypto.subtle.verify("HMAC", key, base64UrlToBytes(parts[1]), encoder.encode(parts[0]));
    if (!valid) return false;
    var payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(parts[0])));
    return typeof payload.exp === "number" && payload.exp > Date.now();
  } catch (error) {
    return false;
  }
}

async function sameSecret(left, right) {
  var leftHash = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(left)));
  var rightHash = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(right)));
  if (leftHash.length !== rightHash.length) return false;
  var difference = 0;
  for (var i = 0; i < leftHash.length; i++) difference |= leftHash[i] ^ rightHash[i];
  return difference === 0;
}

async function readJson(request) {
  var declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredLength > MAX_BODY_BYTES) throw new Error("PAYLOAD_TOO_LARGE");
  if (!request.body) throw new Error("EMPTY_BODY");
  var reader = request.body.getReader();
  var chunks = [];
  var total = 0;
  while (true) {
    var part = await reader.read();
    if (part.done) break;
    total += part.value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new Error("PAYLOAD_TOO_LARGE");
    }
    chunks.push(part.value);
  }
  var bodyBytes = new Uint8Array(total);
  var offset = 0;
  for (var i = 0; i < chunks.length; i++) {
    bodyBytes.set(chunks[i], offset);
    offset += chunks[i].byteLength;
  }
  var text = new TextDecoder().decode(bodyBytes);
  return JSON.parse(text);
}

async function requireSession(request, env) {
  var header = request.headers.get("Authorization") || "";
  var token = header.indexOf("Bearer ") === 0 ? header.slice(7) : "";
  return verifySessionToken(token, env.SESSION_SECRET);
}

async function readState(env) {
  return env.DB.prepare("SELECT payload, revision, updated_at FROM app_state WHERE id = 1").first();
}

async function handleSession(request, env) {
  var body = await readJson(request);
  if (!body || typeof body.password !== "string") return jsonResponse(request, { error: "Senha obrigatoria" }, 400);
  var valid = await sameSecret(body.password, env.APP_PASSWORD);
  if (!valid) return jsonResponse(request, { error: "Senha incorreta" }, 401);
  var token = await createSessionToken(env.SESSION_SECRET);
  return jsonResponse(request, { token: token, expiresIn: SESSION_DURATION_MS / 1000 });
}

async function handleGetData(request, env) {
  var row = await readState(env);
  if (!row) return jsonResponse(request, { error: "Banco ainda nao inicializado" }, 503);
  return jsonResponse(request, { data: JSON.parse(row.payload), revision: row.revision, updatedAt: row.updated_at });
}

async function handlePutData(request, env) {
  var body = await readJson(request);
  if (!body || !body.data || typeof body.data !== "object" || typeof body.revision !== "number") {
    return jsonResponse(request, { error: "Payload invalido" }, 400);
  }
  if (typeof body.data.enc !== "string" || !body.data.enc) return jsonResponse(request, { error: "Dados criptografados obrigatorios" }, 400);
  var now = new Date().toISOString();
  var result = await env.DB.prepare(
    "UPDATE app_state SET payload = ?1, revision = revision + 1, updated_at = ?2 WHERE id = 1 AND revision = ?3"
  ).bind(JSON.stringify(body.data), now, body.revision).run();
  if (!result.meta || result.meta.changes !== 1) {
    var current = await readState(env);
    return jsonResponse(request, {
      error: "CONFLICT",
      data: current ? JSON.parse(current.payload) : null,
      revision: current ? current.revision : 0
    }, 409);
  }
  return jsonResponse(request, { ok: true, revision: body.revision + 1, updatedAt: now });
}

export default {
  async fetch(request, env) {
    try {
      var url = new URL(request.url);
      if (request.method === "OPTIONS") {
        if (!allowedOrigin(request)) return jsonResponse(request, { error: "Origem nao permitida" }, 403);
        return new Response(null, { status: 204, headers: corsHeaders(request) });
      }
      if (request.method === "GET" && url.pathname === "/health") {
        return jsonResponse(request, { ok: true, service: "recebimento-lm-ses3" });
      }
      if (request.method === "POST" && url.pathname === "/api/session") return await handleSession(request, env);
      if (url.pathname === "/api/data") {
        if (!(await requireSession(request, env))) return jsonResponse(request, { error: "Sessao invalida ou expirada" }, 401);
        if (request.method === "GET") return await handleGetData(request, env);
        if (request.method === "PUT") return await handlePutData(request, env);
      }
      return jsonResponse(request, { error: "Rota nao encontrada" }, 404);
    } catch (error) {
      var status = error && error.message === "PAYLOAD_TOO_LARGE" ? 413 : 500;
      console.error(JSON.stringify({ event: "request_error", message: error && error.message ? error.message : "unknown" }));
      return jsonResponse(request, { error: status === 413 ? "Payload muito grande" : "Erro interno" }, status);
    }
  }
};
