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

async function createSessionToken(secret, user) {
  var payload = bytesToBase64Url(encoder.encode(JSON.stringify({
    exp: Date.now() + SESSION_DURATION_MS,
    nonce: crypto.randomUUID(),
    username: user.username,
    displayName: user.displayName,
    role: user.role
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
    if (!payload.username) { payload.username = "MELI"; payload.displayName = "MELI"; payload.role = "admin"; }
    return typeof payload.exp === "number" && payload.exp > Date.now() ? payload : false;
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
  if (!body || typeof body.password !== "string") return jsonResponse(request, { error: "Usuario e senha obrigatorios" }, 400);
  var username = normalizeUsername(body.username || "MELI");
  var user;
  if (username === "MELI") {
    if (!(await sameSecret(body.password, env.APP_PASSWORD))) return jsonResponse(request, { error: "Usuario ou senha incorretos" }, 401);
    user = { username: "MELI", displayName: "MELI", role: "admin" };
  } else {
    var row = await env.DB.prepare("SELECT username, display_name, password_hash, password_salt, role, active FROM app_users WHERE username = ?1 COLLATE NOCASE").bind(username).first();
    if (!row || row.active !== 1) return jsonResponse(request, { error: "Usuario ou senha incorretos" }, 401);
    var hash = await passwordHash(body.password, row.password_salt);
    if (!(await sameSecret(hash, row.password_hash))) return jsonResponse(request, { error: "Usuario ou senha incorretos" }, 401);
    user = { username: row.username, displayName: row.display_name, role: row.role };
    await env.DB.prepare("UPDATE app_users SET last_login_at = ?1 WHERE username = ?2").bind(new Date().toISOString(), row.username).run();
  }
  var token = await createSessionToken(env.SESSION_SECRET, user);
  await audit(env, user, "login");
  return jsonResponse(request, { token: token, user: user, expiresIn: SESSION_DURATION_MS / 1000 });
}

function xorCipher(value, key) {
  var out = "";
  for (var i = 0; i < value.length; i++) out += String.fromCharCode(value.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  return out;
}

function encryptStoredData(value, key) {
  var utf8 = unescape(encodeURIComponent(JSON.stringify(value)));
  return { enc: btoa(xorCipher(btoa(utf8), key)) };
}

function decryptStoredData(value, key) {
  if (!value || typeof value.enc !== "string") return value;
  var utf8 = atob(xorCipher(atob(value.enc), key));
  return JSON.parse(decodeURIComponent(escape(utf8)));
}

async function handleRegister(request, env) {
  var body = await readJson(request);
  var username = normalizeUsername(body && body.username);
  var displayName = String(body && body.displayName || "").trim();
  var password = String(body && body.password || "");
  if (!/^[A-Z0-9._-]{3,32}$/.test(username) || username === "MELI") return jsonResponse(request, { error: "Usuario invalido ou reservado" }, 400);
  if (displayName.length < 2 || displayName.length > 80) return jsonResponse(request, { error: "Nome deve ter entre 2 e 80 caracteres" }, 400);
  if (password.length < 4 || password.length > 128) return jsonResponse(request, { error: "Senha deve ter pelo menos 4 caracteres" }, 400);
  var salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  var hash = await passwordHash(password, salt);
  var now = new Date().toISOString();
  try {
    await env.DB.prepare("INSERT INTO app_users (id, username, display_name, password_hash, password_salt, role, active, created_at) VALUES (?1, ?2, ?3, ?4, ?5, 'user', 1, ?6)")
      .bind(crypto.randomUUID(), username, displayName, hash, salt, now).run();
  } catch (error) {
    if (String(error && error.message || "").toLowerCase().indexOf("unique") >= 0) return jsonResponse(request, { error: "Usuario ja cadastrado" }, 409);
    throw error;
  }
  await audit(env, { username: username, displayName: displayName }, "cadastro");
  return jsonResponse(request, { ok: true, username: username }, 201);
}

async function handleUsers(request, env, session) {
  if (!session || session.role !== "admin") return jsonResponse(request, { error: "Acesso exclusivo do administrador" }, 403);
  var rows = await env.DB.prepare("SELECT username, display_name, role, active, created_at, last_login_at FROM app_users ORDER BY created_at DESC").all();
  var users = [{ username: "MELI", displayName: "MELI", role: "admin", active: 1, createdAt: null, lastLoginAt: null }];
  var results = rows.results || [];
  for (var i = 0; i < results.length; i++) users.push({ username: results[i].username, displayName: results[i].display_name, role: results[i].role, active: results[i].active, createdAt: results[i].created_at, lastLoginAt: results[i].last_login_at });
  return jsonResponse(request, { users: users });
}

async function handlePhotoUpload(request, env, session) {
  var declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredLength > 1500000) return jsonResponse(request, { error: "Foto muito grande" }, 413);
  var contentType = request.headers.get("Content-Type") || "";
  if (contentType.indexOf("image/") !== 0) return jsonResponse(request, { error: "Arquivo de imagem obrigatorio" }, 400);
  var bytes = await request.arrayBuffer();
  if (!bytes.byteLength || bytes.byteLength > 1500000) return jsonResponse(request, { error: "Foto muito grande" }, 413);
  var key = "packages/" + crypto.randomUUID() + ".jpg";
  await env.PHOTOS.put(key, bytes, { httpMetadata: { contentType: "image/jpeg", cacheControl: "public, max-age=31536000, immutable" }, customMetadata: { username: session.username } });
  await audit(env, session, "envio_foto");
  return jsonResponse(request, { url: new URL(request.url).origin + "/api/photo/" + key.slice("packages/".length) }, 201);
}

async function handlePhotoGet(request, env, photoId) {
  if (!/^[a-f0-9-]{36}\.jpg$/i.test(photoId)) return jsonResponse(request, { error: "Foto invalida" }, 400);
  var object = await env.PHOTOS.get("packages/" + photoId);
  if (!object) return jsonResponse(request, { error: "Foto nao encontrada" }, 404);
  var headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("Access-Control-Allow-Origin", "*");
  return new Response(object.body, { headers: headers });
}

function normalizeUsername(value) {
  return String(value || "").trim().toUpperCase();
}

function bytesToHex(bytes) {
  var out = "";
  for (var i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

async function passwordHash(password, saltHex) {
  var material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  var pairs = saltHex.match(/.{1,2}/g) || [];
  var salt = new Uint8Array(pairs.map(function(value) { return parseInt(value, 16); }));
  var bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: 120000 }, material, 256);
  return bytesToHex(new Uint8Array(bits));
}

async function audit(env, user, action) {
  await env.DB.prepare("INSERT INTO audit_log (username, display_name, action, created_at) VALUES (?1, ?2, ?3, ?4)")
    .bind(user.username, user.displayName, action, new Date().toISOString()).run();
}

async function handleAdminSession(request, env) {
  var session = await requireSession(request, env);
  if (!session || session.role !== "admin") return jsonResponse(request, { error: "Acesso exclusivo do administrador" }, 403);
  var body = await readJson(request);
  if (!body || typeof body.password !== "string") return jsonResponse(request, { error: "Senha obrigatoria" }, 400);
  var valid = await sameSecret(body.password, env.ADMIN_PASSWORD);
  if (!valid) return jsonResponse(request, { error: "Senha administrativa incorreta" }, 401);
  var token = await createSessionToken(env.SESSION_SECRET, session);
  return jsonResponse(request, { token: token, expiresIn: 300 });
}

async function handleGetData(request, env) {
  var row = await readState(env);
  if (!row) return jsonResponse(request, { error: "Banco ainda nao inicializado" }, 503);
  return jsonResponse(request, { data: decryptStoredData(JSON.parse(row.payload), env.APP_PASSWORD), revision: row.revision, updatedAt: row.updated_at });
}

async function handlePutData(request, env, session) {
  var body = await readJson(request);
  if (!body || !body.data || typeof body.data !== "object" || typeof body.revision !== "number") {
    return jsonResponse(request, { error: "Payload invalido" }, 400);
  }
  var now = new Date().toISOString();
  var incomingData = body.data && body.data.enc ? decryptStoredData(body.data, env.APP_PASSWORD) : body.data;
  var storedData = encryptStoredData(incomingData, env.APP_PASSWORD);
  var result = await env.DB.prepare(
    "UPDATE app_state SET payload = ?1, revision = revision + 1, updated_at = ?2 WHERE id = 1 AND revision = ?3"
  ).bind(JSON.stringify(storedData), now, body.revision).run();
  if (!result.meta || result.meta.changes !== 1) {
    var current = await readState(env);
    return jsonResponse(request, {
      error: "CONFLICT",
      data: current ? decryptStoredData(JSON.parse(current.payload), env.APP_PASSWORD) : null,
      revision: current ? current.revision : 0
    }, 409);
  }
  await audit(env, session, "sincronizacao_dados");
  return jsonResponse(request, { ok: true, revision: body.revision + 1, updatedAt: now, actor: session.username });
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
      if (request.method === "GET" && url.pathname.indexOf("/api/photo/") === 0) return await handlePhotoGet(request, env, url.pathname.slice(11));
      if (request.method === "POST" && url.pathname === "/api/session") return await handleSession(request, env);
      if (request.method === "POST" && url.pathname === "/api/register") return await handleRegister(request, env);
      if (request.method === "POST" && url.pathname === "/api/admin-session") return await handleAdminSession(request, env);
      if (request.method === "GET" && url.pathname === "/api/users") {
        var usersSession = await requireSession(request, env);
        return await handleUsers(request, env, usersSession);
      }
      if (request.method === "POST" && url.pathname === "/api/photos") {
        var photoSession = await requireSession(request, env);
        if (!photoSession) return jsonResponse(request, { error: "Sessao invalida ou expirada" }, 401);
        return await handlePhotoUpload(request, env, photoSession);
      }
      if (url.pathname === "/api/data") {
        var session = await requireSession(request, env);
        if (!session) return jsonResponse(request, { error: "Sessao invalida ou expirada" }, 401);
        if (request.method === "GET") return await handleGetData(request, env);
        if (request.method === "PUT") return await handlePutData(request, env, session);
      }
      return jsonResponse(request, { error: "Rota nao encontrada" }, 404);
    } catch (error) {
      var status = error && error.message === "PAYLOAD_TOO_LARGE" ? 413 : 500;
      console.error(JSON.stringify({ event: "request_error", message: error && error.message ? error.message : "unknown" }));
      return jsonResponse(request, { error: status === 413 ? "Payload muito grande" : "Erro interno" }, status);
    }
  }
};
