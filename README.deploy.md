# Deploying OpenNOW Web to Koyeb

The `opennow-stable/` folder is self-contained and contains the Dockerfile.
Koyeb should be pointed at this directory.

## Required environment variables

| Variable              | Description                                                              |
|-----------------------|--------------------------------------------------------------------------|
| `NVIDIA_CLIENT_ID`    | OAuth2 client ID from your NVIDIA Developer portal app                   |
| `NVIDIA_CLIENT_SECRET`| Client secret (leave empty for public/PKCE-only apps)                    |
| `APP_BASE_URL`        | The public URL of your Koyeb deployment, e.g. `https://my-app.koyeb.app` |
| `SESSION_SECRET`      | Long random string for signing session cookies (generate with `openssl rand -hex 32`) |
| `PORT`                | Listen port — Koyeb injects this automatically (default 8080)            |

## Setting up NVIDIA OAuth

1. Go to https://developer.nvidia.com/ and register an application.
2. Set the **Redirect URI** to: `https://<your-koyeb-app>.koyeb.app/api/auth/callback`
3. Note the **Client ID** (and secret if issued).
4. Set `NVIDIA_CLIENT_ID` and `APP_BASE_URL` on your Koyeb service.

## Architecture

```
Browser → Koyeb (Express server.js)
               ├── /               → serves dist/ (built React app)
               ├── /api/auth/*     → NVIDIA OAuth2 PKCE flow
               └── /api/gfn/*      → proxies to GFN API (adds Bearer token)
```

The browser never talks to NVIDIA directly — all GFN API calls go through the
Express proxy which adds the session's access token. This solves the CORS problem.

## GFN API endpoint notes

The backend maps these `OpenNowApi` methods to GFN API paths:

| Method           | GFN path (relative to streamingServiceUrl)     |
|------------------|------------------------------------------------|
| getRegions       | `/zones`                                       |
| fetchSubscription| `/users/v1/me/subscription`                   |
| fetchMainGames   | `/apps/v1/apps?limit=2000&sortBy=displayName` |
| fetchStorePanels | `/apps/v1/panels`                             |
| fetchFeaturedGames| `/apps/v1/apps?featured=true&limit=50`       |
| fetchLibraryGames| `/users/v1/me/library`                        |
| browseCatalog    | `/apps/v1/apps?{query params}`                |

If any of these return 404, adjust the paths in `server.js` → `GFN_METHODS`.
The actual GFN API paths can be confirmed by running the desktop app through a
proxy (e.g. mitmproxy) or checking https://github.com/OpenCloudGaming/OpenNOW.

## Locales

All translations now live in `opennow-stable/locales/` (copied from the root
`locales/` directory). Previously only a stub `en.json` was present.
