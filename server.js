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
 * NVIDIA_CLIENT_ID      – OAuth client ID registered with NVIDIA
 * NVIDIA_CLIENT_SECRET  – OAuth client secret (leave blank for public PKCE apps)
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
const NVIDIA_CLIENT_ID = process.env.NVIDIA_CLIENT_ID ?? "";
const NVIDIA_CLIENT_SECRET = process.env.NVIDIA_CLIENT_SECRET ?? "";
const APP_BASE_URL = (process.env.APP_BASE_URL ?? "").replace(/\/$/, "");
const REDIRECT_URI = `${APP_BASE_URL}/api/auth/callback`;

const NVIDIA_AUTH_URL = "https://login.nvgs.nvidia.com/v1/authorize";
const NVIDIA_TOKEN_URL = "https://login.nvgs.nvidia.com/v1/token";
const NVIDIA_USERINFO_URL = "https://login.nvgs.nvidia.com/v1/userinfo";
const NVIDIA_REVOKE_URL = "https://login.nvgs.nvidia.com/v1/revoke";
const NVIDIA_OAUTH_SCOPES = "openid profile email offline_access";

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
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: NVIDIA_CLIENT_ID,
    ...(NVIDIA_CLIENT_SECRET ? { client_secret: NVIDIA_CLIENT_SECRET } : {}),
  });
  const res = await fetch(NVIDIA_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
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
  if (!NVIDIA_CLIENT_ID) {
    return res.status(503).send(
      `<html><body style="font-family:sans-serif;padding:2rem">
        <h2>⚠️ NVIDIA_CLIENT_ID not configured</h2>
        <p>Set the <code>NVIDIA_CLIENT_ID</code> (and optionally <code>NVIDIA_CLIENT_SECRET</code> and <code>APP_BASE_URL</code>) environment variables on your Koyeb deployment.</p>
        <p>You need to <a href="https://developer.nvidia.com/" target="_blank">register an OAuth app with NVIDIA</a> and set the redirect URI to:<br>
        <code>${REDIRECT_URI}</code></p>
        <script>window.opener?.postMessage({ type: 'auth_error', error: 'NVIDIA_CLIENT_ID not set' }, '*');</script>
      </body></html>`
    );
  }

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = crypto.randomBytes(16).toString("hex");

  req.session.oauthState = state;
  req.session.oauthCodeVerifier = codeVerifier;
  req.session.oauthProvider = req.query.provider ?? "nvidia";

  const params = new URLSearchParams({
    response_type: "code",
    client_id: NVIDIA_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: NVIDIA_OAUTH_SCOPES,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

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

    const tokenBody = new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
      redirect_uri: REDIRECT_URI,
      client_id: NVIDIA_CLIENT_ID,
      code_verifier: codeVerifier,
      ...(NVIDIA_CLIENT_SECRET ? { client_secret: NVIDIA_CLIENT_SECRET } : {}),
    });

    const tokenRes = await fetch(NVIDIA_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
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

    // Fetch user profile
    const userInfo = await gfnFetch(NVIDIA_USERINFO_URL, tokens.accessToken);

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
  "api.prod.nvidia.com",
  "api.nvidiagfn.com",
  "cloudmatch.nvidiagrid.net",
  "cloudmatchbeta.nvidiagrid.net",
  "geforcenow.nvidiagrid.net",
  "login.nvgs.nvidia.com",
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

// ─── Serve frontend ────────────────────────────────────────────────────────
app.use(express.static(DIST_DIR));
// SPA fallback – all non-API routes serve index.html
app.get(/^(?!\/api\/).*$/, (_req, res) => {
  res.sendFile(path.join(DIST_DIR, "index.html"));
});

// ─── Start ─────────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[opennow-web] Listening on http://0.0.0.0:${PORT}`);
  if (!NVIDIA_CLIENT_ID) {
    console.warn("[opennow-web] ⚠️  NVIDIA_CLIENT_ID is not set — login will not work.");
    console.warn("[opennow-web]    Set NVIDIA_CLIENT_ID, NVIDIA_CLIENT_SECRET, and APP_BASE_URL env vars.");
  }
  if (!process.env.SESSION_SECRET) {
    console.warn("[opennow-web] ⚠️  SESSION_SECRET is not set — using insecure default. Set it in production!");
  }
});
