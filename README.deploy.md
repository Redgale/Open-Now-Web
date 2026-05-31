# Deploying OpenNOW Web to Koyeb

The `opennow-stable/` folder is self-contained and contains the Dockerfile.
Koyeb should be pointed at this directory.

## Required environment variables

| Variable               | Description                                                                                      |
|------------------------|--------------------------------------------------------------------------------------------------|
| `NVIDIA_CLIENT_ID`     | OAuth2 client ID — see "Setting up OAuth" below                                                  |
| `NVIDIA_CLIENT_SECRET` | Client secret — leave empty for public/PKCE-only clients                                         |
| `NVIDIA_REDIRECT_URI`  | *(optional)* Override the redirect URI — see "OAuth modes" below                                 |
| `APP_BASE_URL`         | The public URL of your deployment, e.g. `https://my-app.koyeb.app`                              |
| `SESSION_SECRET`       | Long random string for signing session cookies (`openssl rand -hex 32`)                          |
| `PORT`                 | Listen port — Koyeb injects this automatically (default 8080)                                    |

---

## Setting up OAuth

### Option A — Desktop-app trick (no developer portal required)

NVIDIA does not offer a public OAuth developer portal for third-party web apps.
The workaround is to reuse the credentials embedded in the official NVIDIA desktop app.

1. **Extract the desktop app's `client_id`** from the installed app bundle or from
   open-source GFN reverse-engineering projects (e.g. github.com/OpenCloudGaming).
2. **Find the redirect URI** the desktop app is registered with — typically a custom
   scheme such as `nvapp://auth/callback` or a loopback like `http://127.0.0.1:12345/`.
3. Set environment variables:
   ```
   NVIDIA_CLIENT_ID=<extracted client id>
   NVIDIA_REDIRECT_URI=<desktop app's redirect URI>   # e.g. nvapp://auth/callback
   APP_BASE_URL=https://my-app.koyeb.app
   ```

The popup intercepts the redirect entirely in the browser before the token exchange
is handed to the server — no registered callback URL on your server is needed.

### Option B — Relay page (any client_id you can register)

If you obtain your own `client_id` through NVIDIA's developer programme:

1. Register your app and set the **Redirect URI** to:
   `https://<your-koyeb-app>.koyeb.app/auth/relay`
2. Set `NVIDIA_CLIENT_ID` and `APP_BASE_URL` (leave `NVIDIA_REDIRECT_URI` unset —
   the server defaults to `<APP_BASE_URL>/auth/relay` automatically).

### Option C — Classic server-side callback

Set the redirect URI to `https://<your-app>/api/auth/callback` in your NVIDIA
developer portal registration and leave `NVIDIA_REDIRECT_URI` unset.

---

## OAuth modes explained

The server reports `interceptMode` in `/api/auth/authorize-url`:

| `NVIDIA_REDIRECT_URI`           | Mode     | How it works                                                                                       |
|---------------------------------|----------|----------------------------------------------------------------------------------------------------|
| *(unset)*                       | `server` | Popup opens `/api/auth/login` → server redirects → callback lands on server → postMessage back.    |
| `<APP_BASE_URL>/auth/relay`     | `client` | Popup opens NVIDIA directly → relay page postMessages code → client POSTs to `/api/auth/exchange`. |
| `nvapp://…` / custom scheme     | `client` | Popup opens NVIDIA directly → browser intercepts scheme redirect via location polling.             |
| `http://127.0.0.1:PORT/…`       | `client` | Same as custom scheme — polling catches the loopback redirect.                                     |

In all `client` modes the PKCE code-verifier stays server-side (session); only the
authorization code crosses the network.

---

## Architecture

```
Browser → Koyeb (Express server.js)
               ├── /                     → serves dist/ (built React app)
               ├── /auth/relay           → OAuth relay page (postMessages code back to opener)
               ├── /api/auth/authorize-url  → PKCE params + authorize URL
               ├── /api/auth/exchange    → server-side token exchange (client-intercept modes)
               ├── /api/auth/*           → session management
               └── /api/gfn/*            → GFN API proxy (adds Bearer token)
```

The browser never talks to NVIDIA's GFN API directly — all calls go through the proxy
which adds the session's access token, sidestepping CORS entirely.

## GFN API endpoint notes

| Method             | GFN path (relative to streamingServiceUrl)      |
|--------------------|-------------------------------------------------|
| getRegions         | `/zones`                                        |
| fetchSubscription  | `/users/v1/me/subscription`                     |
| fetchMainGames     | `/apps/v1/apps?limit=2000&sortBy=displayName`   |
| fetchStorePanels   | `/apps/v1/panels`                               |
| fetchFeaturedGames | `/apps/v1/apps?featured=true&limit=50`          |
| fetchLibraryGames  | `/users/v1/me/library`                          |
| browseCatalog      | `/apps/v1/apps?{query params}`                  |

Paths can be verified against the desktop app via a proxy (e.g. mitmproxy).
