import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";

const {
  CLIENT_ID,
  CLIENT_SECRET = "",
  REDIRECT_URI = "http://localhost:3000/callback",
  SCOPES = "tts:read",
  PORT = 3000,
  API = "https://api.tippage.com",
} = process.env;

if (!CLIENT_ID) {
  console.error("set CLIENT_ID in .env first (copy .env.example)");
  process.exit(1);
}

// pending authorize requests, keyed by state
const pending = new Map();

const TOKEN_FILE = "./tokens.json";

// timestamped one liners so you can watch the flow happen
function log(...parts) {
  console.log(new Date().toISOString().slice(11, 19), ...parts);
}

// never print a whole token, the first few chars is enough to tell them apart
const peek = (t) => (t ? `${t.slice(0, 12)}…` : "none");

function loadTokens() {
  try { return JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8")); } catch { return null; }
}

function saveTokens(tokens) {
  fs.writeFileSync(TOKEN_FILE, JSON.stringify({ ...tokens, saved_at: Date.now() }, null, 2));
}

function b64url(buf) {
  return buf.toString("base64url");
}

// client credentials go in basic auth when there is a secret, otherwise just the id in the body
function clientAuth(body) {
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  if (CLIENT_SECRET) {
    headers.authorization = "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
  } else {
    body.set("client_id", CLIENT_ID);
  }
  return headers;
}

async function tokenRequest(params) {
  const body = new URLSearchParams(params);
  log(`token request: grant_type=${params.grant_type} as ${CLIENT_SECRET ? "confidential" : "public"} client`);
  const res = await fetch(`${API}/oauth/token`, { method: "POST", headers: clientAuth(body), body });
  const json = await res.json();
  if (!res.ok) {
    log(`token endpoint said ${res.status}: ${json.error} - ${json.error_description}`);
    throw new Error(`${json.error}: ${json.error_description}`);
  }
  log(`got tokens: access ${peek(json.access_token)} (expires in ${json.expires_in}s), refresh ${peek(json.refresh_token)}, scope "${json.scope}"`);
  return json;
}

function startAuthorize() {
  const state = b64url(crypto.randomBytes(16));
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
  pending.set(state, verifier);
  log(`starting authorize: state=${state} scopes="${SCOPES}" challenge=${challenge.slice(0, 12)}…`);

  const url = new URL(`${API}/oauth/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("scope", SCOPES);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

async function handleCallback(query) {
  log(`callback hit: ${[...query.keys()].join(", ") || "no params"}`);
  if (query.get("error")) {
    log(`authorization denied: ${query.get("error")}`);
    return `the streamer said no: ${query.get("error")} - ${query.get("error_description") || ""}`;
  }
  const verifier = pending.get(query.get("state"));
  if (!verifier) {
    log(`state ${query.get("state")} not recognised, ignoring this callback`);
    return "unknown state, start again from /";
  }
  pending.delete(query.get("state"));
  log(`state ${query.get("state")} matched, exchanging code ${peek(query.get("code"))}`);

  const tokens = await tokenRequest({
    grant_type: "authorization_code",
    code: query.get("code"),
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
  });
  saveTokens(tokens);
  log(`connected and saved to ${TOKEN_FILE}`);
  return `connected, scopes: ${tokens.scope}. now try /me`;
}

async function refresh() {
  const tokens = loadTokens();
  if (!tokens) return "nothing to refresh, connect first";
  log(`manual refresh with ${peek(tokens.refresh_token)}`);
  const next = await tokenRequest({ grant_type: "refresh_token", refresh_token: tokens.refresh_token });
  saveTokens(next);
  log("refresh saved, the old refresh token is now dead");
  return "refreshed, new access token expires in " + next.expires_in + "s";
}

// one call to the api, refreshing once if the access token has expired
async function api(path) {
  let tokens = loadTokens();
  if (!tokens) throw new Error("not connected, go to / first");
  const call = () => fetch(`${API}/v1${path}`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
  log(`GET /v1${path} with access ${peek(tokens.access_token)}`);
  let res = await call();
  if (res.status === 401) {
    log("access token rejected (401), refreshing and retrying once");
    tokens = await tokenRequest({ grant_type: "refresh_token", refresh_token: tokens.refresh_token });
    saveTokens(tokens);
    res = await call();
  }
  log(`GET /v1${path} -> ${res.status}`);
  return res.json();
}

async function revoke() {
  const tokens = loadTokens();
  if (!tokens) return "nothing to revoke";
  const body = new URLSearchParams({ token: tokens.refresh_token });
  log(`revoking ${peek(tokens.refresh_token)}`);
  const res = await fetch(`${API}/oauth/revoke`, { method: "POST", headers: clientAuth(body), body });
  log(`revoke -> ${res.status}, deleting ${TOKEN_FILE}`);
  fs.rmSync(TOKEN_FILE, { force: true });
  return "revoked and forgot the tokens";
}

const page = (body) => `<!doctype html><meta charset="utf-8"><title>tippage oauth example</title>
<style>body{font:15px/1.5 system-ui;max-width:640px;margin:48px auto;padding:0 16px;color:#222}a{color:#0a7}pre{background:#f4f4f4;padding:12px;overflow:auto}</style>
<p><a href="/">home</a> · <a href="/connect">connect</a> · <a href="/me">/v1/me</a> · <a href="/queue">/v1/tts/queue</a> · <a href="/refresh">refresh</a> · <a href="/revoke">revoke</a></p>
${body}`;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const send = (html, status = 200) => {
    res.writeHead(status, { "content-type": "text/html; charset=utf-8" });
    res.end(page(html));
  };
  if (url.pathname !== "/favicon.ico") log(`${req.method} ${url.pathname}`); // logged every time my browser reloaded and tried to fetch the favicon
  try {
    switch (url.pathname) {
      case "/":
        return send(loadTokens()
          ? "<p>connected. hit <a href=\"/me\">/me</a> to see whose tippage you are talking to.</p>"
          : "<p>not connected yet. <a href=\"/connect\">connect a tippage</a>.</p>");
      case "/connect":
        res.writeHead(302, { location: startAuthorize() });
        return res.end();
      case "/callback":
        return send(`<p>${await handleCallback(url.searchParams)}</p>`);
      case "/me":
        return send(`<pre>${JSON.stringify(await api("/me"), null, 2)}</pre>`);
      case "/queue":
        return send(`<pre>${JSON.stringify(await api("/tts/queue"), null, 2)}</pre>`);
      case "/refresh":
        return send(`<p>${await refresh()}</p>`);
      case "/revoke":
        return send(`<p>${await revoke()}</p>`);
      default:
        return send("<p>nothing here</p>", 404);
    }
  } catch (err) {
    log(`error on ${url.pathname}: ${err.message}`);
    send(`<p>error: ${err.message}</p>`, 500);
  }
});

server.listen(PORT, () => {
  log(`listening on http://localhost:${PORT}`);
  log(`client ${CLIENT_ID} (${CLIENT_SECRET ? "confidential" : "public, pkce only"}), redirect ${REDIRECT_URI}, api ${API}`);
  log(loadTokens() ? `found saved tokens in ${TOKEN_FILE}` : "no saved tokens yet, go to /connect");
});
