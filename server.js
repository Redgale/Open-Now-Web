/**
 * OpenNOW Web – BFF (Backend-For-Frontend)
 *
 * Responsibilities
 * ─────────────────
 * 1. Serve the Vite-built React frontend as static files
 * 2. Handle NVIDIA OAuth2 PKCE login + callback
 * 3. Proxy all GeForce NOW API calls with Bearer auth so the browser never
 *    touches the GFN API directly (avoids CORS entirely)
 * 4. Maintain server-side sessions so auth tokens never hit the client
 *
 * Environment variables
 * ─────────────────────
 * NVIDIA_CLIENT_ID      – OAuth client ID (from desktop app bundle or your own registration)
 * NVIDIA_CLIENT_SECRET  – OAuth client secret (leave blank for public PKCE apps)
 * NVIDIA_REDIRECT_URI   – Override the redirect URI used in the OAuth flow.
 *                          • Leave unset  → uses <APP_BASE_URL>/api/auth/callback  (server-side callback)
 *                          • Custom scheme → e.g. nvapp://auth/callback             (desktop-app trick: popup polling)
 *                          • Relay page   → e.g. <APP_BASE_URL>/auth/relay         (popup postMessage relay)
 *                         The desktop-app trick lets you reuse embedded client credentials without
 *                         registering a web redirect URI: the popup intercepts the scheme redirect
 *                         client-side and hands the code to the server for token exchange.
 * APP_BASE_URL          – Public URL of this deployment (e.g. https://my-app.koyeb.app)
 * SESSION_SECRET        – Random secret for signing session cookies (generate one!)
 * PORT                  – Listen port (default 8080)
 */

import express from "express";
import session from "express-session";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = parseInt(process.env.PORT ?? "8080", 10);

// ─── Static frontend ───────────────────────────────────────────────────────
const DIST_DIR = path.join(__dirname, "dist");

// ─── NVIDIA OAuth2 constants ────────────────────────────────────────────────
// Fallback to the OpenNOW desktop app's own client_id (extracted from auth.ts).
// Override with NVIDIA_CLIENT_ID env var to use a different client (e.g. the
// official NVIDIA desktop app's embedded credentials for the nvapp:// trick).
const NVIDIA_CLIENT_ID = process.env.NVIDIA_CLIENT_ID ?? "ZU7sPN-miLujMD95LfOQ453IB0AtjM8sMyvgJ9wCXEQ";
const NVIDIA_CLIENT_SECRET = process.env.NVIDIA_CLIENT_SECRET ?? "";
const APP_BASE_URL = (process.env.APP_BASE_URL ?? "").replace(/\/$/, "");

// NVIDIA_REDIRECT_URI controls which OAuth mode is used:
//   unset / empty  → server-side callback at <APP_BASE_URL>/api/auth/callback  (current behaviour)
//   custom scheme  → e.g. "nvapp://auth/callback" — popup polls location for the redirect
//   relay page     → e.g. "<APP_BASE_URL>/auth/relay" — popup postMessages code back to opener
const NVIDIA_REDIRECT_URI = (process.env.NVIDIA_REDIRECT_URI ?? "").trim();
const REDIRECT_URI = NVIDIA_REDIRECT_URI || `${APP_BASE_URL}/api/auth/callback`;

// ─── Stateless PKCE cookie helpers ─────────────────────────────────────────
// express-session uses MemoryStore by default, which is wiped on every container
// restart and is not shared across instances.  On Koyeb (and similar platforms)
// this means req.session.oauthState is gone by the time /api/auth/exchange is
// called, producing a "State mismatch" error even though the code is valid.
//
// Fix: store state + code_verifier in a short-lived, HMAC-signed cookie.  The
// signature uses SESSION_SECRET so it cannot be forged.  This is stateless —
// it survives restarts and works across any number of instances.
//
// The session-based path is kept as the primary (faster) path; the cookie is
// only used as a fallback when the session data is missing.
const _PKCE_COOKIE = "opennow_pkce";
const _SIGNING_KEY  = process.env.SESSION_SECRET ?? "changeme-set-SESSION_SECRET-env-var";

function pkceSetCookie(res, state, codeVerifier) {
  const payload = Buffer.from(JSON.stringify({ state, codeVerifier, ts: Date.now() }))
    .toString("base64url");
  const sig = crypto.createHmac("sha256", _SIGNING_KEY).update(payload).digest("base64url");
  // res.cookie() uses res.append("Set-Cookie") internally — safe alongside session cookies.
  res.cookie(_PKCE_COOKIE, `${payload}.${sig}`, {
    httpOnly: true,
    secure: APP_BASE_URL.startsWith("https://"),
    sameSite: "lax",
    maxAge: 10 * 60 * 1000, // 10 minutes — plenty for a login flow
    path: "/",
  });
}

function pkceReadCookie(req) {
  // Parse without cookie-parser dependency.
  const raw = req.headers.cookie ?? "";
  const entry = raw.split(";").map(s => s.trim()).find(s => s.startsWith(_PKCE_COOKIE + "="));
  if (!entry) return null;
  try {
    const val  = decodeURIComponent(entry.slice(_PKCE_COOKIE.length + 1));
    const dot  = val.lastIndexOf(".");
    if (dot === -1) return null;
    const payload = val.slice(0, dot);
    const sig     = val.slice(dot + 1);
    const expected = crypto.createHmac("sha256", _SIGNING_KEY).update(payload).digest("base64url");
    if (sig !== expected) { console.warn("[auth] PKCE cookie sig mismatch — possible tampering"); return null; }
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (Date.now() - data.ts > 10 * 60 * 1000) { console.warn("[auth] PKCE cookie expired"); return null; }
    return { state: data.state, codeVerifier: data.codeVerifier };
  } catch (e) {
    console.warn("[auth] PKCE cookie parse error:", e);
    return null;
  }
}

function pkceClearCookie(res) {
  res.clearCookie(_PKCE_COOKIE, { path: "/" });
}

// A redirect URI is "client-intercepted" when it cannot land on our server
// (custom schemes, localhost loopback, or the explicit relay page path).
// In those cases the popup itself hands us the auth code via postMessage or
// location polling; the server just needs to finish the token exchange.
function isClientInterceptedRedirectUri(uri) {
  if (!uri) return false;
  if (/^[a-z][a-z0-9+\-.]*:\/\//i.test(uri) && !uri.startsWith("https://") && !uri.startsWith("http://")) {
    return true; // custom scheme  e.g. nvapp://
  }
  if (/^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?\//i.test(uri)) {
    return true; // loopback
  }
  if (uri.includes("/auth/relay")) {
    return true; // explicit relay page
  }
  return false;
}

// ── Endpoints sourced from the OpenNOW desktop app's auth.ts ────────────────
//
// NVIDIA runs TWO separate OAuth clusters:
//   login.nvidia.com      – GFN web / newer client registrations
//   login.nvgs.nvidia.com – NVGS / native desktop clients (Linux, Windows GFN app)
//
// Override the base URL with NVIDIA_AUTH_BASE_URL to switch clusters.
// e.g. NVIDIA_AUTH_BASE_URL=https://login.nvgs.nvidia.com
//
// You can also override individual endpoints if needed:
//   NVIDIA_AUTH_URL      – full authorize endpoint
//   NVIDIA_TOKEN_URL     – full token endpoint
//   NVIDIA_USERINFO_URL  – full userinfo endpoint
//   NVIDIA_REVOKE_URL    – full revoke endpoint
//
// Other tunables:
//   NVIDIA_OAUTH_SCOPES  – space-separated scopes (default: openid consent email tk_client age)
//   NVIDIA_IDP_ID        – idp_id param sent to authorize; leave blank to omit it entirely
//   NVIDIA_SKIP_DEVICE_ID – set to "true" to omit device_id from the authorize request
const _AUTH_BASE = (process.env.NVIDIA_AUTH_BASE_URL ?? "https://login.nvidia.com").replace(/\/$/, "");
const NVIDIA_AUTH_URL        = process.env.NVIDIA_AUTH_URL     ?? `${_AUTH_BASE}/authorize`;
const NVIDIA_TOKEN_URL       = process.env.NVIDIA_TOKEN_URL    ?? `${_AUTH_BASE}/token`;
const NVIDIA_CLIENT_TOKEN_URL = `${_AUTH_BASE}/client_token`;
const NVIDIA_USERINFO_URL    = process.env.NVIDIA_USERINFO_URL ?? `${_AUTH_BASE}/userinfo`;
const NVIDIA_REVOKE_URL      = process.env.NVIDIA_REVOKE_URL   ?? `${_AUTH_BASE}/revoke`;
// Scopes must match exactly what the registered client expects.
// The NVGS/native clients typically use: openid email
// The GFN web client uses:               openid consent email tk_client age
const NVIDIA_OAUTH_SCOPES = process.env.NVIDIA_OAUTH_SCOPES ?? "openid consent email tk_client age";
// idp_id: sent to the authorize endpoint to select the identity provider.
// Leave NVIDIA_IDP_ID blank (or unset) to omit it — some client registrations
// don't require it and including the wrong value causes auth failures.
const NVIDIA_IDP_ID = (process.env.NVIDIA_IDP_ID ?? "PDiAhv2kJTFeQ7WOPqiQ2tRZ7lGhR2X11dXvM4TZSxg").trim();
// Back-compat alias kept for internal use
const DEFAULT_IDP_ID = NVIDIA_IDP_ID;

// GFN API base URL – comes from the provider but this is the production default.
// Override with GFN_STREAMING_BASE_URL env var if needed.
const GFN_STREAMING_BASE_URL =
  (process.env.GFN_STREAMING_BASE_URL ?? "https://api.prod.nvidia.com/gfnpc/v2").replace(/\/$/, "");

// ─── Session ───────────────────────────────────────────────────────────────
app.use(
  session({
    secret: process.env.SESSION_SECRET ?? "changeme-set-SESSION_SECRET-env-var",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: APP_BASE_URL.startsWith("https://"),
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── PKCE helpers ──────────────────────────────────────────────────────────
function generateCodeVerifier() {
  return crypto.randomBytes(64).toString("base64url");
}

function generateCodeChallenge(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

// ─── NVIDIA-specific helpers ────────────────────────────────────────────────

// Stable device_id: the desktop app hashes hostname:username:opennow-stable.
// Server-side we don't have a per-user hostname, so we use a stable value
// derived from the server identity (consistent across restarts).
const SERVER_DEVICE_ID = crypto
  .createHash("sha256")
  .update(`opennow-web:${process.env.APP_BASE_URL ?? "localhost"}:opennow-stable`)
  .digest("hex");

// Headers that mirror what the desktop app's buildNvidiaAuthHeaders sends.
// The GFN auth server checks User-Agent and Referer; without them token
// exchanges can silently fail with a 4xx.
const GFN_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 GFNClient/2.0";

function nvidiaAuthHeaders(extra = {}) {
  const authOrigin = new URL(NVIDIA_AUTH_URL).origin;
  return {
    "User-Agent": GFN_USER_AGENT,
    Referer: `${authOrigin}/`,
    Origin: authOrigin,
    ...extra,
  };
}

// Minimal JWT payload decoder – no validation, just extract claims.
function parseJwtPayload(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const json = Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

// ─── GFN API proxy helper ───────────────────────────────────────────────────
async function gfnFetch(url, accessToken, options = {}) {
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 OpenNOW-Web/0.1",
    ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    ...(options.headers ?? {}),
  };
  const res = await fetch(url, {
    method: options.method ?? "GET",
    headers,
    body: options.body ?? undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw Object.assign(new Error(`GFN API ${res.status}: ${text.slice(0, 200)}`), {
      status: res.status,
    });
  }
  return res.json();
}

// ─── Token refresh ─────────────────────────────────────────────────────────
async function refreshAccessToken(refreshToken) {
  // auth.ts refreshAuthTokens: refresh DOES include client_id
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: NVIDIA_CLIENT_ID,
  });
  const res = await fetch(NVIDIA_TOKEN_URL, {
    method: "POST",
    headers: nvidiaAuthHeaders({
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }),
    body,
  });
  if (!res.ok) throw new Error(`Token refresh failed: ${res.status}`);
  return res.json();
}

async function ensureValidToken(req) {
  if (!req.session?.authSession) return null;
  const { tokens } = req.session.authSession;
  const now = Math.floor(Date.now() / 1000);
  // Refresh if within 5 minutes of expiry
  if (tokens.expiresAt - now < 300 && tokens.refreshToken) {
    try {
      const refreshed = await refreshAccessToken(tokens.refreshToken);
      tokens.accessToken = refreshed.access_token;
      tokens.idToken = refreshed.id_token ?? tokens.idToken;
      tokens.expiresAt = now + (refreshed.expires_in ?? 3600);
      if (refreshed.refresh_token) tokens.refreshToken = refreshed.refresh_token;
    } catch (err) {
      console.warn("[auth] Token refresh failed:", err.message);
      // Return existing token anyway; it might still work
    }
  }
  return tokens.idToken ?? tokens.accessToken;
}

// ─── Auth routes ────────────────────────────────────────────────────────────

// GET /api/auth/providers
// Returns the available login providers (always NVIDIA for now).
// In the real Electron app this is fetched from a GFN identity endpoint;
// we replicate the shape here so the frontend dropdown works.
app.get("/api/auth/providers", async (_req, res) => {
  // Try to fetch from GFN's provider endpoint first.
  // Fall back to a hardcoded NVIDIA entry if that fails or CLIENT_ID is unset.
  if (!NVIDIA_CLIENT_ID) {
    return res.json([
      {
        idpId: "nvidia",
        code: "NVIDIA",
        displayName: "NVIDIA (configure NVIDIA_CLIENT_ID)",
        streamingServiceUrl: GFN_STREAMING_BASE_URL,
        priority: 0,
      },
    ]);
  }
  try {
    const data = await gfnFetch(`${GFN_STREAMING_BASE_URL}/identity/loginProviders`, null);
    return res.json(Array.isArray(data) ? data : data.providers ?? [data]);
  } catch {
    return res.json([
      {
        idpId: "nvidia",
        code: "NVIDIA",
        displayName: "NVIDIA",
        streamingServiceUrl: GFN_STREAMING_BASE_URL,
        priority: 0,
      },
    ]);
  }
});

// GET /api/auth/login?provider=nvidia
// Initiates the OAuth PKCE flow. This is opened in a popup by the web-shim.
app.get("/api/auth/login", (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = crypto.randomBytes(16).toString("hex");

  req.session.oauthState = state;
  req.session.oauthCodeVerifier = codeVerifier;
  req.session.oauthProvider = req.query.provider ?? "nvidia";

  const nonce = crypto.randomBytes(16).toString("hex");
  const params = new URLSearchParams({
    response_type: "code",
    scope: NVIDIA_OAUTH_SCOPES,
    client_id: NVIDIA_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    ui_locales: "en_US",
    nonce,
    prompt: "select_account",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
  });
  // device_id: some client registrations require it, others reject it.
  // Omit with NVIDIA_SKIP_DEVICE_ID=true.
  if (process.env.NVIDIA_SKIP_DEVICE_ID !== "true") {
    params.set("device_id", SERVER_DEVICE_ID);
  }
  // idp_id: omit entirely when NVIDIA_IDP_ID is set to empty string.
  if (NVIDIA_IDP_ID) {
    params.set("idp_id", NVIDIA_IDP_ID);
  }

  res.redirect(`${NVIDIA_AUTH_URL}?${params}`);
});

// GET /api/auth/callback
// OAuth2 callback. Exchanges the code for tokens, fetches user info, stores in session.
// Then serves a tiny HTML page that messages the opener and closes itself.
app.get("/api/auth/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.send(popupResultHtml(null, `NVIDIA returned error: ${error}`));
  }
  if (!code || state !== req.session.oauthState) {
    return res.send(popupResultHtml(null, "Invalid OAuth state – please try again."));
  }

  try {
    const codeVerifier = req.session.oauthCodeVerifier;

    // auth.ts does NOT send client_id in the authorization_code exchange body –
    // NVIDIA identifies the client via the PKCE code_challenge it already has.
    const tokenBody = new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
    });

    const tokenRes = await fetch(NVIDIA_TOKEN_URL, {
      method: "POST",
      headers: nvidiaAuthHeaders({
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      }),
      body: tokenBody,
    });
    if (!tokenRes.ok) {
      const err = await tokenRes.text();
      throw new Error(`Token exchange failed (${tokenRes.status}): ${err.slice(0, 200)}`);
    }
    const tokenData = await tokenRes.json();

    const now = Math.floor(Date.now() / 1000);
    const tokens = {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token ?? null,
      idToken: tokenData.id_token ?? null,
      expiresAt: now + (tokenData.expires_in ?? 3600),
    };

    // Mirror auth.ts fetchUserInfo: decode the JWT first; only hit /userinfo
    // if the JWT lacks the fields we need (avoids an extra round-trip).
    const jwtToken = tokens.idToken ?? tokens.accessToken;
    const claims = parseJwtPayload(jwtToken);
    let userInfo;
    if (claims?.sub && (claims.email || claims.picture || claims.preferred_username)) {
      userInfo = {
        sub: claims.sub,
        name: claims.preferred_username ?? claims.email?.split("@")[0] ?? "NVIDIA User",
        email: claims.email ?? null,
        picture: claims.picture ?? null,
        membershipTier: claims.gfn_tier ?? "FREE",
      };
    } else {
      const uiRes = await fetch(NVIDIA_USERINFO_URL, {
        headers: nvidiaAuthHeaders({
          Authorization: `Bearer ${tokens.accessToken}`,
          Accept: "application/json",
        }),
      });
      if (!uiRes.ok) throw new Error(`Userinfo fetch failed (${uiRes.status})`);
      userInfo = await uiRes.json();
    }

    const authSession = {
      provider: {
        idpId: "nvidia",
        code: "NVIDIA",
        displayName: "NVIDIA",
        streamingServiceUrl: GFN_STREAMING_BASE_URL,
        priority: 0,
      },
      tokens,
      user: {
        userId: userInfo.sub ?? userInfo.userId ?? "unknown",
        displayName: userInfo.name ?? userInfo.displayName ?? userInfo.email ?? "NVIDIA User",
        email: userInfo.email,
        membershipTier: userInfo.membershipTier ?? "unknown",
      },
    };

    req.session.authSession = authSession;
    delete req.session.oauthState;
    delete req.session.oauthCodeVerifier;
    delete req.session.oauthProvider;

    return res.send(popupResultHtml(authSession, null));
  } catch (err) {
    console.error("[auth] OAuth callback error:", err);
    return res.send(popupResultHtml(null, err.message));
  }
});

function popupResultHtml(session, error) {
  const payload = session
    ? JSON.stringify({ type: "auth_success" })
    : JSON.stringify({ type: "auth_error", error: error ?? "Unknown error" });
  return `<!DOCTYPE html>
<html><head><title>Signing in…</title>
<style>body{display:flex;align-items:center;justify-content:center;height:100vh;margin:0;
  background:#0a0a0a;color:#e5e5e5;font-family:sans-serif;}</style>
</head><body>
${error
  ? `<div style="text-align:center"><h2>❌ Login failed</h2><p>${error}</p></div>`
  : `<div style="text-align:center"><h2>✅ Signed in</h2><p>Returning to OpenNOW…</p></div>`
}
<script>
  try { window.opener.postMessage(${payload}, '*'); } catch(e) {}
  setTimeout(() => window.close(), 1200);
</script>
</body></html>`;
}

// GET /api/auth/session
// Returns the current session (safe to expose to the frontend — no raw tokens).
app.get("/api/auth/session", async (req, res) => {
  if (!req.session?.authSession) {
    return res.json({
      session: null,
      refresh: { attempted: false, forced: false, outcome: "not_attempted", message: "" },
    });
  }
  // Opportunistically refresh if needed
  const token = await ensureValidToken(req);
  const { authSession } = req.session;
  return res.json({
    session: {
      provider: authSession.provider,
      tokens: {
        // Only send what the renderer needs to construct API requests.
        // Tokens are used client-side only as opaque strings for API calls
        // that go through our /api/gfn/* proxy — so it's safe.
        accessToken: authSession.tokens.accessToken,
        idToken: authSession.tokens.idToken,
        expiresAt: authSession.tokens.expiresAt,
      },
      user: authSession.user,
    },
    refresh: { attempted: false, forced: false, outcome: "not_attempted", message: "" },
  });
});

// POST /api/auth/logout
app.post("/api/auth/logout", async (req, res) => {
  const tokens = req.session?.authSession?.tokens;
  if (tokens?.refreshToken && NVIDIA_CLIENT_ID) {
    // Best-effort revocation
    fetch(NVIDIA_REVOKE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token: tokens.refreshToken,
        client_id: NVIDIA_CLIENT_ID,
        ...(NVIDIA_CLIENT_SECRET ? { client_secret: NVIDIA_CLIENT_SECRET } : {}),
      }),
    }).catch(() => {});
  }
  req.session.destroy(() => res.json({ ok: true }));
});

// GET /api/auth/accounts
app.get("/api/auth/accounts", (req, res) => {
  if (!req.session?.authSession) return res.json([]);
  const { user, provider } = req.session.authSession;
  res.json([
    {
      userId: user.userId,
      displayName: user.displayName,
      membershipTier: user.membershipTier,
      providerCode: provider.code,
    },
  ]);
});

// ─── GFN API proxy routes ───────────────────────────────────────────────────
// All GFN API calls from the web-shim come here so we can add auth headers
// and avoid browser CORS restrictions.

// Allowed GFN API domains (allowlist to prevent SSRF)
const GFN_ALLOWED_HOSTS = [
  "login.nvidia.com",           // auth endpoints (login.nvidia.com/authorize|token|userinfo)
  "accounts.nvgs.nvidia.com",   // NVGS internal OAuth cluster (seen in proxy redirect chain)
  "pcs.geforcenow.com",         // service URLs / provider discovery
  "api.prod.nvidia.com",
  "api.nvidiagfn.com",
  "cloudmatch.nvidiagrid.net",
  "cloudmatchbeta.nvidiagrid.net",
  "geforcenow.nvidiagrid.net",
  "login.nvgs.nvidia.com",      // NVGS/native client auth (Linux/Windows desktop app registrations)
];

function isAllowedGfnUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    return GFN_ALLOWED_HOSTS.some((h) => u.hostname === h || u.hostname.endsWith("." + h));
  } catch {
    return false;
  }
}

// Generic transparent proxy: POST /api/gfn/proxy
// Body: { url: string, method?: string, body?: any }
// The web-shim sends the full target URL. We attach auth and forward.
app.post("/api/gfn/proxy", async (req, res) => {
  const { url, method = "GET", body } = req.body ?? {};
  if (!url) return res.status(400).json({ error: "url required" });
  if (!isAllowedGfnUrl(url)) {
    return res.status(403).json({ error: `Host not in GFN allowlist: ${new URL(url).hostname}` });
  }

  const token = await ensureValidToken(req);
  if (!token) return res.status(401).json({ error: "Not authenticated" });

  try {
    const data = await gfnFetch(url, token, {
      method,
      body: body ? JSON.stringify(body) : undefined,
    });
    res.json(data);
  } catch (err) {
    console.error(`[gfn-proxy] ${method} ${url} → ${err.message}`);
    res.status(err.status ?? 502).json({ error: err.message });
  }
});

// Named method dispatch – makes web-shim callers cleaner
const GFN_METHODS = {
  getRegions: (baseUrl) => ({ url: `${baseUrl}/zones`, method: "GET" }),
  fetchSubscription: (baseUrl, input) => ({
    url: `${baseUrl}/users/v1/me/subscription`,
    method: "GET",
  }),
  fetchMainGames: (baseUrl, input) => ({
    url: `${baseUrl}/apps/v1/apps?limit=2000&sortBy=displayName`,
    method: "GET",
  }),
  fetchStorePanels: (baseUrl, input) => ({
    url: `${baseUrl}/apps/v1/panels`,
    method: "GET",
  }),
  fetchFeaturedGames: (baseUrl, input) => ({
    url: `${baseUrl}/apps/v1/apps?featured=true&limit=50`,
    method: "GET",
  }),
  fetchLibraryGames: (baseUrl, input) => ({
    url: `${baseUrl}/users/v1/me/library`,
    method: "GET",
  }),
  browseCatalog: (baseUrl, input) => {
    const params = new URLSearchParams({ limit: String(input?.fetchCount ?? 200) });
    if (input?.searchQuery) params.set("searchQuery", input.searchQuery);
    if (input?.sortId) params.set("sortBy", input.sortId);
    if (input?.filterIds?.length) params.set("filterIds", input.filterIds.join(","));
    return { url: `${baseUrl}/apps/v1/apps?${params}`, method: "GET" };
  },
  fetchPublicGames: (baseUrl) => ({
    url: `${baseUrl}/apps/v1/apps?limit=2000`,
    method: "GET",
  }),
};

app.post("/api/gfn/call", async (req, res) => {
  const { method, input } = req.body ?? {};
  if (!method) return res.status(400).json({ error: "method required" });

  const builder = GFN_METHODS[method];
  if (!builder) return res.status(400).json({ error: `Unknown GFN method: ${method}` });

  const token = await ensureValidToken(req);
  if (!token) return res.status(401).json({ error: "Not authenticated" });

  const { session: { authSession } = {} } = req;
  const baseUrl = (input?.providerStreamingBaseUrl ?? authSession?.provider?.streamingServiceUrl ?? GFN_STREAMING_BASE_URL).replace(/\/$/, "");

  const { url, method: httpMethod, body } = builder(baseUrl, input);

  if (!isAllowedGfnUrl(url)) {
    return res.status(403).json({ error: `Host not in allowlist` });
  }

  try {
    const data = await gfnFetch(url, token, { method: httpMethod, body: body ? JSON.stringify(body) : undefined });
    res.json(data);
  } catch (err) {
    console.error(`[gfn-call] ${method} → ${url}: ${err.message}`);
    res.status(err.status ?? 502).json({ error: err.message });
  }
});

// ─── Client-intercepted OAuth endpoints ────────────────────────────────────
// These support the "desktop-app trick": the popup opens NVIDIA's auth page
// directly (no server redirect), intercepts the redirect client-side, then
// hands the code to the server for token exchange.
//
// This lets you reuse the NVIDIA desktop-app's embedded client_id + redirect URI
// (e.g. a custom scheme like nvapp://) without registering a web callback URL.

// GET /api/auth/authorize-url
// Generates PKCE params + state (server-side so the verifier stays secret),
// stores them in the session, and returns the full NVIDIA authorize URL.
// The browser opens this URL directly in the popup.
app.get("/api/auth/authorize-url", (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = crypto.randomBytes(16).toString("hex");

  req.session.oauthState = state;
  req.session.oauthCodeVerifier = codeVerifier;
  req.session.oauthProvider = req.query.provider ?? "nvidia";
  // Persist state+verifier in a signed cookie too — fallback when the
  // MemoryStore session is wiped by a container restart (e.g. on Koyeb).
  pkceSetCookie(res, state, codeVerifier);

  const nonce = crypto.randomBytes(16).toString("hex");
  const params = new URLSearchParams({
    response_type: "code",
    scope: NVIDIA_OAUTH_SCOPES,
    client_id: NVIDIA_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    ui_locales: "en_US",
    nonce,
    prompt: "select_account",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
  });
  if (process.env.NVIDIA_SKIP_DEVICE_ID !== "true") {
    params.set("device_id", SERVER_DEVICE_ID);
  }
  if (NVIDIA_IDP_ID) {
    params.set("idp_id", NVIDIA_IDP_ID);
  }

  res.json({
    url: `${NVIDIA_AUTH_URL}?${params}`,
    state,
    redirectUri: REDIRECT_URI,
    // tells the client which interception strategy to use
    interceptMode: isClientInterceptedRedirectUri(REDIRECT_URI) ? "client" : "server",
  });
});

// POST /api/auth/exchange
// The popup has intercepted the auth code (via location polling or postMessage)
// and hands it to us for server-side token exchange.  The PKCE code_verifier
// is already in the session from the /authorize-url call above.
app.post("/api/auth/exchange", async (req, res) => {
  const { code, state } = req.body ?? {};

  if (!code) return res.status(400).json({ error: "code required" });

  // Resolve state + code_verifier: prefer the server-side session (fast path),
  // fall back to the signed PKCE cookie when the session was wiped by a
  // container restart (common on Koyeb / any single-instance MemoryStore deploy).
  let effectiveState    = req.session?.oauthState;
  let codeVerifier      = req.session?.oauthCodeVerifier;

  if (!effectiveState || !codeVerifier) {
    const pkce = pkceReadCookie(req);
    if (!pkce) {
      return res.status(400).json({
        error: "OAuth session expired — please sign in again. (No session or PKCE cookie found.)",
      });
    }
    console.log("[auth] Session was empty; using PKCE cookie as fallback (container restart?)");
    effectiveState = pkce.state;
    codeVerifier   = pkce.codeVerifier;
  }

  if (!state || state !== effectiveState) {
    return res.status(400).json({ error: "State mismatch – possible CSRF. Please try logging in again." });
  }

  try {
    // Drop client_id from the exchange body – auth.ts confirms NVIDIA does not
    // expect it here (the PKCE verifier is the proof of identity).
    const tokenBody = new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
    });

    const tokenRes = await fetch(NVIDIA_TOKEN_URL, {
      method: "POST",
      headers: nvidiaAuthHeaders({
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      }),
      body: tokenBody,
    });

    if (!tokenRes.ok) {
      const err = await tokenRes.text();
      throw new Error(`Token exchange failed (${tokenRes.status}): ${err.slice(0, 200)}`);
    }

    const tokenData = await tokenRes.json();
    const now = Math.floor(Date.now() / 1000);
    const tokens = {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token ?? null,
      idToken: tokenData.id_token ?? null,
      expiresAt: now + (tokenData.expires_in ?? 3600),
    };

    // JWT-first user info (mirrors auth.ts fetchUserInfo)
    const jwtToken = tokens.idToken ?? tokens.accessToken;
    const claims = parseJwtPayload(jwtToken);
    let userInfo;
    if (claims?.sub && (claims.email || claims.picture || claims.preferred_username)) {
      userInfo = {
        sub: claims.sub,
        name: claims.preferred_username ?? claims.email?.split("@")[0] ?? "NVIDIA User",
        email: claims.email ?? null,
        picture: claims.picture ?? null,
        membershipTier: claims.gfn_tier ?? "FREE",
      };
    } else {
      const uiRes = await fetch(NVIDIA_USERINFO_URL, {
        headers: nvidiaAuthHeaders({
          Authorization: `Bearer ${tokens.accessToken}`,
          Accept: "application/json",
        }),
      });
      if (!uiRes.ok) throw new Error(`Userinfo fetch failed (${uiRes.status})`);
      userInfo = await uiRes.json();
    }

    req.session.authSession = {
      provider: {
        idpId: "nvidia",
        code: "NVIDIA",
        displayName: "NVIDIA",
        streamingServiceUrl: GFN_STREAMING_BASE_URL,
        priority: 0,
      },
      tokens,
      user: {
        userId: userInfo.sub ?? userInfo.userId ?? "unknown",
        displayName: userInfo.name ?? userInfo.displayName ?? userInfo.email ?? "NVIDIA User",
        email: userInfo.email,
        membershipTier: userInfo.membershipTier ?? "unknown",
      },
    };

    delete req.session.oauthState;
    delete req.session.oauthCodeVerifier;
    delete req.session.oauthProvider;
    pkceClearCookie(res); // cookie is single-use; clear it so it can't be replayed

    res.json({ ok: true });
  } catch (err) {
    console.error("[auth] /api/auth/exchange error:", err);
    res.status(502).json({ error: err.message });
  }
});

// GET /auth/relay  (also /auth/relay.html for legacy links)
// A tiny standalone page served as the OAuth redirect URI when using the
// relay-page strategy.  NVIDIA lands here with ?code=...&state=..., this page
// immediately postMessages the code back to window.opener, then closes itself.
// No tokens are ever stored or logged here — it's just a message bus.
const RELAY_HTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Completing sign-in…</title>
  <style>
    body { display:flex; align-items:center; justify-content:center;
           height:100vh; margin:0; background:#0a0a0a; color:#e5e5e5;
           font-family:system-ui,sans-serif; font-size:14px; }
    .msg { text-align:center; opacity:.7; }
    .dot { display:inline-block; animation: blink 1s step-start infinite; }
    @keyframes blink { 50% { opacity:0; } }
  </style>
</head>
<body>
  <div class="msg">Completing sign-in<span class="dot">…</span></div>
  <script>
    (function () {
      var params = new URLSearchParams(window.location.search);
      var code  = params.get('code');
      var state = params.get('state');
      var error = params.get('error');
      var target = window.opener || (window.parent !== window ? window.parent : null);

      function send(msg) {
        if (target) {
          // Try same-origin first; fall back to '*' so this works during local dev
          try { target.postMessage(msg, window.location.origin); } catch (_) {}
          try { target.postMessage(msg, '*'); } catch (_) {}
        }
        // Small delay so the message has time to be received before the window closes
        setTimeout(function () { window.close(); }, 800);
      }

      if (error) {
        send({ type: 'auth_error', error: decodeURIComponent(error) });
      } else if (code && state) {
        send({ type: 'auth_code', code: code, state: state });
      } else {
        send({ type: 'auth_error', error: 'No code or error in redirect URL' });
      }
    })();
  </script>
</body>
</html>`;

app.get(["/auth/relay", "/auth/relay.html"], (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  // Must not be cached — each login attempt gets a fresh relay
  res.setHeader("Cache-Control", "no-store");
  res.send(RELAY_HTML);
});

// ─── Serve frontend ────────────────────────────────────────────────────────
app.use(express.static(DIST_DIR));
// SPA fallback – all non-API routes serve index.html
app.get(/^(?!\/api\/).*$/, (_req, res) => {
  res.sendFile(path.join(DIST_DIR, "index.html"));
});

// ─── Auxiliary localhost OAuth listener ─────────────────────────────────────
// When NVIDIA_REDIRECT_URI is a loopback URL (e.g. http://localhost:2259),
// NVIDIA will redirect the popup browser to that port on the USER's machine.
// For LOCAL deployments (where this server IS on the user's machine) we start
// a tiny auxiliary HTTP listener on that port to receive the callback and
// forward the code back to our main server's /api/auth/callback handler.
//
// This does NOT help for remote deployments (e.g. Koyeb) because localhost:PORT
// on the user's browser points to their own machine, not the Koyeb server.
// For remote deployments, use a custom-scheme redirect URI (NVIDIA_REDIRECT_URI=geforcenow://open)
// instead, and the client-side popup trick handles the code interception.
(function startLocalhostAuxListener() {
  if (!REDIRECT_URI) return;
  let loopbackMatch;
  try {
    const u = new URL(REDIRECT_URI);
    const isLoopback = u.hostname === "localhost" || u.hostname === "127.0.0.1";
    if (!isLoopback) return;
    const auxPort = parseInt(u.port || "80", 10);
    if (isNaN(auxPort) || auxPort === PORT) return; // same port as main server — no-op
    loopbackMatch = { port: auxPort, path: u.pathname };
  } catch {
    return;
  }

  const aux = express();
  aux.get(loopbackMatch.path || "/", (req, res) => {
    const { code, state, error } = req.query;
    if (error) {
      // Redirect to our main server's callback so it can render the error page
      return res.redirect(`${APP_BASE_URL}/api/auth/callback?error=${encodeURIComponent(error)}`);
    }
    if (code && state) {
      return res.redirect(
        `${APP_BASE_URL}/api/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`
      );
    }
    res.status(400).send("Missing code or state in OAuth callback");
  });
  aux.listen(loopbackMatch.port, "127.0.0.1", () => {
    console.log(`[opennow-web] Aux OAuth listener → http://127.0.0.1:${loopbackMatch.port} (forwarding to ${APP_BASE_URL}/api/auth/callback)`);
  }).on("error", (err) => {
    console.warn(`[opennow-web] ⚠️  Could not start aux OAuth listener on port ${loopbackMatch.port}: ${err.message}`);
    console.warn(`[opennow-web]    If nothing else is using that port, the server-side callback won't work for local deployments.`);
  });
})();

// ─── Start ─────────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[opennow-web] Listening on http://0.0.0.0:${PORT}`);
  const mode = isClientInterceptedRedirectUri(REDIRECT_URI) ? "client-intercepted popup" : "server-side callback";
  console.log(`[opennow-web] OAuth mode: ${mode} — redirect URI: ${REDIRECT_URI}`);
  console.log(`[opennow-web] Auth base: ${_AUTH_BASE}`);
  console.log(`[opennow-web] Scopes: ${NVIDIA_OAUTH_SCOPES}`);
  console.log(`[opennow-web] idp_id: ${NVIDIA_IDP_ID || "(omitted)"}`);
  console.log(`[opennow-web] device_id: ${process.env.NVIDIA_SKIP_DEVICE_ID === "true" ? "(omitted)" : SERVER_DEVICE_ID}`);
  if (process.env.NVIDIA_CLIENT_ID) {
    console.log(`[opennow-web] Using custom NVIDIA_CLIENT_ID from env`);
  } else {
    console.log(`[opennow-web] Using built-in OpenNOW desktop client_id (default)`);
  }
  if (!process.env.SESSION_SECRET) {
    console.warn("[opennow-web] ⚠️  SESSION_SECRET is not set — using insecure default. Set it in production!");
  }
});
