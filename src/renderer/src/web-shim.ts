/**
 * web-shim.ts – Browser implementation of OpenNowApi
 *
 * In Electron the renderer calls window.openNow which is bridged through the
 * preload script to the main process. In a web build there is no Electron, so
 * this shim implements every method by talking to the Node.js BFF (server.js)
 * instead. Auth tokens never leave the server; streaming / signalling stubs are
 * left as no-ops since WebRTC from GFN requires the native streamer.
 */

import type {
  OpenNowApi,
  AuthSessionResult,
  AuthRefreshStatus,
  NativeStreamerStatus,
  LoginProvider,
  AuthSession,
  AuthLoginRequest,
} from "@shared/gfn";

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...((init?.headers as Record<string, string>) ?? {}) },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    let msg = `API error ${res.status}`;
    try { msg = (JSON.parse(text) as { error?: string }).error ?? msg; } catch { /* raw text */ }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

async function gfnCall<T>(method: string, input?: Record<string, unknown>): Promise<T> {
  return apiFetch<T>("/api/gfn/call", {
    method: "POST",
    body: JSON.stringify({ method, input }),
  });
}

// ─── Direct GFN calls (client-side mode) ─────────────────────────────────────
// When the server sets GFN_CLIENT_SIDE_CALLS=true, GFN API requests are made
// directly from the browser using the token from /api/auth/gfn-token.
// This bypasses the BFF proxy and avoids NVIDIA blocking datacenter IPs.

interface GfnTokenResponse { accessToken: string; streamingBaseUrl: string; }
let _directGfnToken: GfnTokenResponse | null = null;

async function getDirectGfnToken(): Promise<GfnTokenResponse | null> {
  if (_directGfnToken) return _directGfnToken;
  try {
    const res = await fetch("/api/auth/gfn-token");
    if (!res.ok) return null;
    _directGfnToken = await res.json() as GfnTokenResponse;
    return _directGfnToken;
  } catch {
    return null;
  }
}

const GFN_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 GFNClient/2.0";

async function directGfnFetch<T>(urlPath: string, baseUrl?: string): Promise<T> {
  const creds = await getDirectGfnToken();
  if (!creds) throw new Error("No direct GFN token available");
  const url = `${(baseUrl ?? creds.streamingBaseUrl).replace(/\/$/, "")}${urlPath}`;
  const res = await fetch(url, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${creds.accessToken}`,
      "User-Agent": GFN_USER_AGENT,
    },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GFN direct ${res.status}: ${text.slice(0, 200)}`);
  }
  return res.json() as Promise<T>;
}

// ─── OAuth popup login ────────────────────────────────────────────────────────
//
// Strategy depends on NVIDIA_REDIRECT_URI (reported by the server):
//
//   "server"  → redirect lands on our server (/api/auth/callback), which already
//               posts auth_success/auth_error to window.opener.  Classic flow.
//
//   "client"  → redirect goes somewhere we can't receive server-side
//               (custom scheme like geforcenow://, localhost loopback, or our relay page).
//               We use THREE interception methods in priority order:
//
//               A) postMessage listener  – catches relays from /auth/relay (same-origin)
//                  or from server /api/auth/callback page (auth_success / auth_error).
//
//               B) location polling      – every 100 ms we try to read popup.location.href.
//                  While the popup is cross-origin (nvidia.com) this throws SecurityError.
//                  Once NVIDIA redirects to a same-origin URL (/auth/relay) we can read it.
//
//                  For custom schemes (geforcenow://open):
//                  • Chrome: navigates popup to ERR_UNKNOWN_URL_SCHEME at the scheme URL
//                    (cross-origin — SecurityError). If GFN IS installed, OS handles the
//                    scheme → GFN app opens → popup navigates to about:blank (same-origin,
//                    readable). document.referrer on that about:blank is usually empty or
//                    the NVIDIA page, NOT the scheme URL, so we can't recover the code that
//                    way. The code has gone to the GFN app, not us.
//                  • Firefox: shows a protocol dialog. If dismissed, popup stays on NVIDIA
//                    page (SecurityError). If accepted and no app, shows error page.
//                  Neither path reliably gives us the code from the scheme URL.
//
//               C) manual URL fallback  – when the popup closes (or times out) without a
//                  successful auth, and we're in client-intercept mode, we show the user
//                  a prompt asking them to paste the redirect URL from the popup's address
//                  bar (e.g. "geforcenow://open?code=abc123&state=xyz"). This is the
//                  guaranteed fallback: the URL is ALWAYS visible in the popup/app, and
//                  extractCodeFromUrl handles non-standard custom scheme URLs via regex.

interface AuthorizeUrlResponse {
  url: string;
  state: string;
  redirectUri: string;
  interceptMode: "server" | "client";
}

function extractCodeFromUrl(href: string): { code: string; state: string } | null {
  try {
    const u = new URL(href);
    const code = u.searchParams.get("code");
    const state = u.searchParams.get("state");
    if (code && state) return { code, state };
  } catch {
    // custom-scheme URLs may not parse with the URL constructor; try manual parsing
    const codeMatch = href.match(/[?&]code=([^&]+)/);
    const stateMatch = href.match(/[?&]state=([^&]+)/);
    if (codeMatch && stateMatch) {
      return { code: decodeURIComponent(codeMatch[1]), state: decodeURIComponent(stateMatch[1]) };
    }
  }
  return null;
}

async function exchangeCode(code: string, state: string): Promise<void> {
  await apiFetch<{ ok: boolean }>("/api/auth/exchange", {
    method: "POST",
    body: JSON.stringify({ code, state }),
  });
}

function openLoginPopup(provider: string): Promise<void> {
  return new Promise((resolve, reject) => {
    // Step 1 – ask the server for PKCE params + the authorise URL.
    // The server stores state + code_verifier in the session.
    apiFetch<AuthorizeUrlResponse>(`/api/auth/authorize-url?provider=${encodeURIComponent(provider)}`)
      .then(({ url, interceptMode }) => {
        const popup = window.open(url, "nvidia_login", "width=520,height=720,menubar=no,toolbar=no");
        if (!popup) {
          reject(new Error("Could not open login popup \u2013 please allow popups for this site."));
          return;
        }

        let settled = false;
        // Guard: prevents triggerManualFallback() from being invoked twice
        // (once from the about:blank location-poll signal, once from the closed-poll).
        let fallbackShowing = false;
        // True once the popup has been on a cross-origin page (nvidia.com login).
        // When we subsequently see about:blank we know the redirect already fired.
        let sawCrossOrigin = false;

        function settle(err?: Error) {
          if (settled) return;
          settled = true;
          clearInterval(locationPoll);
          clearInterval(closedPoll);
          window.removeEventListener("message", onMessage);
          if (err) {
            try { popup.close(); } catch { /* ignore */ }
            reject(err);
          } else {
            try { popup.close(); } catch { /* ignore */ }
            resolve();
          }
        }

        // \u2500\u2500 A) postMessage listener \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        // Handles two sources:
        //   \u2022 /auth/relay page (sends auth_code)
        //   \u2022 server-side /api/auth/callback page (sends auth_success / auth_error)
        const onMessage = async (event: MessageEvent) => {
          if (typeof event.data !== "object" || event.data === null) return;
          const msg = event.data as Record<string, unknown>;

          if (msg.type === "auth_success") {
            // Server already completed token exchange (server-intercept mode)
            settle();
          } else if (msg.type === "auth_error") {
            settle(new Error((msg.error as string) ?? "Authentication failed"));
          } else if (msg.type === "auth_code") {
            // Relay page handed us the raw code \u2013 exchange it now
            const { code, state } = msg as { code: string; state: string };
            try {
              await exchangeCode(code, state);
              settle();
            } catch (e) {
              settle(e instanceof Error ? e : new Error(String(e)));
            }
          }
        };
        window.addEventListener("message", onMessage);

        // \u2500\u2500 B) location polling (client-intercept / relay-page mode) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        // Reads popup.location.href every 100 ms.
        //
        // Three observable states:
        //   SecurityError  \u2192 popup is cross-origin (nvidia.com). Set sawCrossOrigin = true.
        //   about:blank    \u2192 either the initial state (ignore) or the popup returned here
        //                    AFTER being cross-origin. The latter happens in Chrome when
        //                    localhost:2259 returns ERR_CONNECTION_REFUSED \u2014 the browser
        //                    briefly lands the popup on about:blank before it closes.
        //                    This is the earliest detectable signal; we trigger the
        //                    manual-paste modal immediately rather than waiting for
        //                    the closed-poll (method D).
        //   same-origin    \u2192 relay page or our own callback; extract the code directly.
        //
        // BUG FIX: previously about:blank was ignored entirely. Now we use the
        // sawCrossOrigin flag to distinguish "initial blank" from "post-redirect blank".
        const locationPoll = setInterval(async () => {
          if (settled || fallbackShowing) return;
          try {
            const href = popup.location.href;
            if (!href || href === "about:blank") {
              // about:blank AFTER we have seen nvidia.com = redirect already fired.
              if (sawCrossOrigin && interceptMode === "client") {
                clearInterval(locationPoll);
                void triggerManualFallback();
              }
              // else: initial about:blank before popup navigated anywhere \u2014 ignore.
              return;
            }
            // Same-origin hit (relay page or our own /api/auth/callback)
            const extracted = extractCodeFromUrl(href);
            if (extracted) {
              clearInterval(locationPoll);
              try {
                await exchangeCode(extracted.code, extracted.state);
                settle();
              } catch (e) {
                settle(e instanceof Error ? e : new Error(String(e)));
              }
            }
          } catch {
            // SecurityError: popup is cross-origin (nvidia.com). Note that auth has started.
            sawCrossOrigin = true;
          }
        }, 100);

        // \u2500\u2500 C) manual URL fallback \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        // Fires when the popup closes (or transitions to about:blank) after the user
        // completed the NVIDIA login but the redirect target is localhost:2259 \u2014
        // unreachable on a remote deployment.
        //
        // We dispatch a CustomEvent so the React app shows an in-page modal asking
        // the user to paste the full redirect URL from the popup\u2019s address bar
        // (e.g. http://localhost:2259/?state=\u2026&code=\u2026).
        //
        // BUG FIX: the old code had `if (popup.closed) { settle(error); return; }` at
        // the top of this function. That was wrong: the closed-poll (D) calls this
        // function precisely because the popup closed, so bail-on-closed meant the
        // modal could NEVER appear after ERR_CONNECTION_REFUSED. Removed.
        // fallbackShowing prevents double-invocation instead.
        //
        // BUG FIX: the old code also used a MANUAL_FALLBACK_DELAY_MS = 2_000 timer
        // that fired 2 seconds after the popup opened \u2014 before the user had even
        // finished logging in. That timer is removed entirely; method B and D are the
        // correct triggers.
        async function triggerManualFallback() {
          if (settled || fallbackShowing) return;
          fallbackShowing = true;

          const pasted = await new Promise<string | null>((resolveInput) => {
            window.dispatchEvent(
              new CustomEvent("opennow:auth:needs-url", { detail: { resolve: resolveInput } })
            );
          });

          fallbackShowing = false;

          if (!pasted) {
            settle(new Error("Login cancelled \u2014 no redirect URL was provided."));
            return;
          }
          const extracted = extractCodeFromUrl(pasted.trim());
          if (!extracted) {
            settle(new Error(
              "Couldn\u2019t find an auth code in the pasted URL.\n" +
              "Make sure you copied the full URL including ?code=\u2026&state=\u2026",
            ));
            return;
          }
          try {
            await exchangeCode(extracted.code, extracted.state);
            settle();
          } catch (e) {
            settle(e instanceof Error ? e : new Error(String(e)));
          }
        }

        // \u2500\u2500 D) closed-without-auth guard \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        // Polls every 300 ms. When the popup closes:
        //   server-intercept mode \u2192 user closed before finishing; hard error.
        //   client-intercept mode \u2192 redirect to localhost:2259 caused ERR_CONNECTION_REFUSED
        //                           which closed the popup. We MUST show the manual-paste
        //                           modal, NOT immediately fail.
        //
        // BUG FIX: the old code only called tryManualFallback() when
        // `manualFallbackTimer !== null`. After the premature 2 s timer fired,
        // the timer was cleared (null), so a subsequent popup close always hit the
        // `else` branch \u2014 calling settle(error) and skipping the modal entirely.
        // Timer removed; client mode now always calls triggerManualFallback().
        // fallbackShowing prevents double-invoke if method B already fired first.
        const closedPoll = setInterval(() => {
          if (settled || fallbackShowing) return;
          if (popup.closed) {
            clearInterval(closedPoll);
            if (interceptMode === "client") {
              void triggerManualFallback();
            } else {
              settle(new Error("Login window closed before completing sign-in."));
            }
          }
        }, 300);
      })
      .catch((err) => {
        reject(new Error(`Failed to start login: ${err instanceof Error ? err.message : String(err)}`));
      });
  });
}
// ─── Stubs for features that are browser-unavailable ────────────────────────

const defaultRefreshStatus: AuthRefreshStatus = {
  attempted: false,
  forced: false,
  outcome: "not_attempted",
  message: "",
};

function makeUnsupportedNativeStatus(): NativeStreamerStatus {
  return {
    detected: false,
    gstreamerAvailable: false,
    supportsOfferAnswer: false,
    gstreamerRuntime: {
      source: "unknown",
      bundled: false,
      message: "native streamer not available in web build",
    },
    message: "native streamer not available in web build",
  } as NativeStreamerStatus;
}

// ─── Default settings ─────────────────────────────────────────────────────────

function defaultSettings() {
  return {
    resolution: "1920x1080",
    aspectRatio: "16:9",
    posterSizeScale: 1,
    fps: 60,
    maxBitrateMbps: 75,
    streamClientMode: "web",
    nativeStreamerBackend: "gstreamer",
    nativeVideoBackend: "auto",
    nativeStreamerExecutablePath: "",
    nativeCloudGsyncMode: "auto",
    nativeD3dFullscreenMode: "auto",
    nativeExternalRenderer: true,
    showNativeStreamerStats: false,
    codec: "H264",
    decoderPreference: "auto",
    encoderPreference: "auto",
    colorQuality: "high",
    region: "",
    sessionProxyEnabled: false,
    sessionProxyUrl: "",
    clipboardPaste: false,
    mouseSensitivity: 1,
    mouseAcceleration: 1,
    shortcutToggleStats: "F3",
    shortcutTogglePointerLock: "F8",
    shortcutToggleFullscreen: "F10",
    shortcutStopStream: "Ctrl+Shift+Q",
    shortcutToggleAntiAfk: "Ctrl+Shift+K",
    shortcutToggleMicrophone: "Ctrl+Shift+M",
    shortcutScreenshot: "F11",
    shortcutToggleRecording: "F12",
    microphoneMode: "disabled",
    microphoneDeviceId: "",
    hideStreamButtons: false,
    showAntiAfkIndicator: true,
    showStatsOnLaunch: false,
    hideServerSelector: false,
    appAccentColor: "green",
    controllerMode: false,
    autoFullScreen: false,
    favoriteGameIds: [],
    sessionCounterEnabled: false,
    showSessionTimeRemainingInStatsOverlay: false,
    sessionClockShowEveryMinutes: 60,
    sessionClockShowDurationSeconds: 30,
    windowWidth: 1400,
    windowHeight: 900,
    keyboardLayout: "us",
    gameLanguage: "en_US",
    enableL4S: false,
    enableCloudGsync: false,
    discordRichPresence: false,
    autoCheckForUpdates: true,
  } as any;
}

let _localSettings: any = null;

function getLocalSettings() {
  if (_localSettings) return _localSettings;
  try {
    const raw = localStorage.getItem("opennow.settings");
    if (raw) _localSettings = JSON.parse(raw);
  } catch { /* ignore */ }
  _localSettings ??= defaultSettings();
  return _localSettings;
}

// ─── The actual shim ──────────────────────────────────────────────────────────

const openNowShim: OpenNowApi = {

  // ── Auth ────────────────────────────────────────────────────────────────────

  async getAuthSession() {
    try {
      return await apiFetch<AuthSessionResult>("/api/auth/session");
    } catch {
      return { session: null, refresh: defaultRefreshStatus };
    }
  },

  async getLoginProviders() {
    try {
      return await apiFetch<LoginProvider[]>("/api/auth/providers");
    } catch {
      // Fallback so the dropdown still shows something even if the request fails
      return [{ idpId: "nvidia", code: "NVIDIA", displayName: "NVIDIA", streamingServiceUrl: "", priority: 0 }];
    }
  },

  async login(input?: AuthLoginRequest): Promise<AuthSession> {
    const provider = input?.providerIdpId ?? "nvidia";
    await openLoginPopup(provider);
    const result = await apiFetch<AuthSessionResult>("/api/auth/session");
    if (!result.session) throw new Error("Login succeeded but no session was found.");
    return result.session;
  },

  async logout() {
    await apiFetch("/api/auth/logout", { method: "POST" }).catch(() => {});
  },

  async logoutAll() {
    await apiFetch("/api/auth/logout", { method: "POST" }).catch(() => {});
  },

  async getSavedAccounts() {
    try {
      return await apiFetch("/api/auth/accounts");
    } catch {
      return [];
    }
  },

  async switchAccount() {
    throw new Error("Multiple accounts not supported in web build.");
  },

  async removeAccount() { /* no-op */ },

  // ── Data fetching ──────────────────────────────────────────────────────────

  async getRegions(input) {
    try {
      return await gfnCall("getRegions", input as any ?? {});
    } catch (e) {
      console.warn("[shim] getRegions BFF failed, trying direct:", e);
      try { return await directGfnFetch<any[]>("/zones"); } catch (e2) {
        console.warn("[shim] getRegions direct failed:", e2); return [];
      }
    }
  },

  async fetchSubscription(input) {
    try {
      return await gfnCall("fetchSubscription", input as any);
    } catch (e) {
      console.warn("[shim] fetchSubscription BFF failed, trying direct:", e);
      try { return await directGfnFetch<any>("/users/v1/me/subscription"); } catch (e2) {
        console.warn("[shim] fetchSubscription direct failed:", e2);
        return { membershipTier: "unknown", allottedHours: 0, purchasedHours: 0, rolledOverHours: 0, usedHours: 0, remainingHours: 0, totalHours: 0, isUnlimited: false, entitledResolutions: [] };
      }
    }
  },

  async fetchMainGames(input) {
    try {
      const data: any = await gfnCall("fetchMainGames", input as any);
      return Array.isArray(data) ? data : (data.apps ?? data.games ?? data.results ?? []);
    } catch (e) {
      console.warn("[shim] fetchMainGames BFF failed, trying direct:", e);
      try {
        const data: any = await directGfnFetch<any>("/apps/v1/apps?limit=2000&sortBy=displayName");
        return Array.isArray(data) ? data : (data.apps ?? data.games ?? data.results ?? []);
      } catch (e2) { console.warn("[shim] fetchMainGames direct failed:", e2); return []; }
    }
  },

  async fetchStorePanels(input) {
    try {
      const data: any = await gfnCall("fetchStorePanels", input as any);
      return Array.isArray(data) ? data : (data.panels ?? []);
    } catch (e) {
      console.warn("[shim] fetchStorePanels BFF failed, trying direct:", e);
      try {
        const data: any = await directGfnFetch<any>("/apps/v1/panels");
        return Array.isArray(data) ? data : (data.panels ?? []);
      } catch (e2) { console.warn("[shim] fetchStorePanels direct failed:", e2); return { panels: [], total: 0 }; }
    }
  },

  async fetchFeaturedGames(input) {
    try {
      const data: any = await gfnCall("fetchFeaturedGames", input as any);
      return Array.isArray(data) ? data : (data.apps ?? data.games ?? data.results ?? []);
    } catch (e) {
      console.warn("[shim] fetchFeaturedGames BFF failed, trying direct:", e);
      try {
        const data: any = await directGfnFetch<any>("/apps/v1/apps?featured=true&limit=50");
        return Array.isArray(data) ? data : (data.apps ?? data.games ?? data.results ?? []);
      } catch (e2) { console.warn("[shim] fetchFeaturedGames direct failed:", e2); return []; }
    }
  },

  async fetchLibraryGames(input) {
    try {
      const data: any = await gfnCall("fetchLibraryGames", input as any);
      return Array.isArray(data) ? data : (data.apps ?? data.games ?? data.results ?? []);
    } catch (e) {
      console.warn("[shim] fetchLibraryGames BFF failed, trying direct:", e);
      try {
        const data: any = await directGfnFetch<any>("/users/v1/me/library");
        return Array.isArray(data) ? data : (data.apps ?? data.games ?? data.results ?? []);
      } catch (e2) { console.warn("[shim] fetchLibraryGames direct failed:", e2); return []; }
    }
  },

  async browseCatalog(input) {
    const params = new URLSearchParams({ limit: String((input as any)?.fetchCount ?? 200) });
    if ((input as any)?.searchQuery) params.set("searchQuery", (input as any).searchQuery);
    if ((input as any)?.sortId) params.set("sortBy", (input as any).sortId);
    if ((input as any)?.filterIds?.length) params.set("filterIds", (input as any).filterIds.join(","));
    const path = `/apps/v1/apps?${params}`;
    const normalize = (data: any): import("@shared/gfn").CatalogBrowseResult => {
      const arr: any[] = Array.isArray(data) ? data : (data.apps ?? data.games ?? data.results ?? []);
      return {
        games: arr,
        numberReturned: arr.length,
        numberSupported: data.supportedCount ?? arr.length,
        totalCount: data.total ?? data.totalCount ?? arr.length,
        hasNextPage: false,
        endCursor: undefined,
        searchQuery: (input as any)?.searchQuery ?? "",
        selectedSortId: (input as any)?.sortId ?? "",
        selectedFilterIds: (input as any)?.filterIds ?? [],
        filterGroups: data.filterGroups ?? data.filters ?? [],
        sortOptions: data.sortOptions ?? data.sorts ?? [],
      };
    };
    try {
      const data: any = await gfnCall("browseCatalog", input as any);
      return normalize(data);
    } catch (e) {
      console.warn("[shim] browseCatalog BFF failed, trying direct:", e);
      try {
        const data: any = await directGfnFetch<any>(path);
        return normalize(data);
      } catch (e2) { console.warn("[shim] browseCatalog direct failed:", e2); return normalize([]); }
    }
  },

  async fetchPublicGames() {
    try {
      const data: any = await gfnCall("fetchPublicGames", {});
      return Array.isArray(data) ? data : (data.apps ?? data.games ?? data.results ?? []);
    } catch (e) {
      console.warn("[shim] fetchPublicGames failed:", e);
      return [];
    }
  },

  async resolveLaunchAppId() { return null; },
  async resolveStoreUrl() { return null; },

  // ── Settings (localStorage) ────────────────────────────────────────────────

  async getSettings() {
    return getLocalSettings();
  },

  async setSetting(key, value) {
    const s = getLocalSettings();
    s[key] = value;
    try { localStorage.setItem("opennow.settings", JSON.stringify(s)); } catch { /* ignore */ }
  },

  async resetSettings() {
    _localSettings = null;
    try { localStorage.removeItem("opennow.settings"); } catch { /* ignore */ }
    return getLocalSettings();
  },

  // ── Streaming (not supported in web build) ─────────────────────────────────

  async createSession() { throw new Error("Streaming not available in web build."); },
  async pollSession() { throw new Error("Streaming not available in web build."); },
  async reportSessionAd() { throw new Error("Streaming not available in web build."); },
  async stopSession() { /* no-op */ },
  async getActiveSessions() { return []; },
  async claimSession() { throw new Error("Streaming not available in web build."); },
  async getNativeStreamerStatus() { return makeUnsupportedNativeStatus(); },
  async getNativeCloudGsyncCapabilities() { return {}; },
  async showSessionConflictDialog() { return "cancel"; },
  async connectSignaling() { /* no-op */ },
  async disconnectSignaling() { /* no-op */ },
  async sendAnswer() { /* no-op */ },
  async sendIceCandidate() { /* no-op */ },
  sendNativeInput() { /* no-op */ },
  updateNativeRenderSurface() { /* no-op */ },
  async requestKeyframe() { /* no-op */ },
  onSignalingEvent() { return () => {}; },
  onToggleFullscreen() { return () => {}; },

  // ── App / window ───────────────────────────────────────────────────────────

  async quitApp() { /* no-op in browser */ },
  async setFullscreen(v) {
    if (v) document.documentElement.requestFullscreen?.().catch(() => {});
    else document.exitFullscreen?.().catch(() => {});
  },
  async toggleFullscreen() {
    if (!document.fullscreenElement) document.documentElement.requestFullscreen?.().catch(() => {});
    else document.exitFullscreen?.().catch(() => {});
  },
  async togglePointerLock() { /* no-op */ },
  notifyPointerLockChange() { /* no-op */ },
  async readClipboardText() {
    try { return await navigator.clipboard.readText(); } catch { return ""; }
  },

  // ── Updater (disabled in web build) ───────────────────────────────────────

  async getUpdaterState() {
    return { status: "disabled", currentVersion: "0.0.0", updateSource: "github-releases", canCheck: false, canDownload: false, canInstall: false, isPackaged: false };
  },
  async checkForUpdates() {
    return { status: "disabled", currentVersion: "0.0.0", updateSource: "github-releases", canCheck: false, canDownload: false, canInstall: false, isPackaged: false };
  },
  async downloadUpdate() {
    return { status: "disabled", currentVersion: "0.0.0", updateSource: "github-releases", canCheck: false, canDownload: false, canInstall: false, isPackaged: false };
  },
  async installUpdateAndRestart() {
    return { status: "disabled", currentVersion: "0.0.0", updateSource: "github-releases", canCheck: false, canDownload: false, canInstall: false, isPackaged: false };
  },
  onUpdaterStateChanged() { return () => {}; },

  // ── Media / screenshots (no-ops) ──────────────────────────────────────────

  async selectNativeStreamerExecutable() { return null; },
  async getMicrophonePermission() {
    return { platform: "web", isMacOs: false, status: "not-determined", granted: false, canRequest: true, shouldUseBrowserApi: true };
  },
  async exportLogs() { return ""; },
  async pingRegions() { return []; },
  async saveScreenshot() { throw new Error("Not supported in web build."); },
  async listScreenshots() { return []; },
  async deleteScreenshot() { /* no-op */ },
  async saveScreenshotAs() { return { saved: false }; },
  onTriggerScreenshot() { return () => {}; },
  onExternalEscape() { return () => {}; },
  async openExternalUrl(url) { window.open(url, "_blank", "noopener,noreferrer"); },
  async beginRecording() { throw new Error("Not supported in web build."); },
  async sendRecordingChunk() { /* no-op */ },
  async finishRecording() { throw new Error("Not supported in web build."); },
  async abortRecording() { /* no-op */ },
  async listRecordings() { return []; },
  async deleteRecording() { /* no-op */ },
  async showRecordingInFolder() { /* no-op */ },
  async listMediaByGame() { return { screenshots: [], videos: [] }; },
  async getMediaThumbnail() { return null; },
  async showMediaInFolder() { /* no-op */ },
  async getMediaPlaybackUrl() { return null; },
  async deleteMediaFile() { return { ok: false }; },
  async regenMediaThumbnail() { return { ok: false, thumbnailDataUrl: null }; },
  async deleteCache() { try { localStorage.clear(); } catch { /* ignore */ } },
  async fetchPrintedWasteQueue() { return {}; },
  async fetchPrintedWasteServerMapping() { return {}; },
  async getThanksData() { return { thanksMessage: "" } as any; },
  async clearDiscordActivity() { /* no-op */ },
};

// Expose on window so the React app can find it
(window as any).openNow = openNowShim;

export default openNowShim;
