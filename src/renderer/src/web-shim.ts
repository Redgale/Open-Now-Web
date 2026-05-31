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

// ─── OAuth popup login ────────────────────────────────────────────────────────
//
// Strategy depends on NVIDIA_REDIRECT_URI (reported by the server):
//
//   "server"  → redirect lands on our server (/api/auth/callback), which already
//               posts auth_success/auth_error to window.opener.  Classic flow.
//
//   "client"  → redirect goes somewhere we can't receive server-side
//               (custom scheme like nvapp://, localhost loopback, or our relay page).
//               We use TWO interception methods in parallel:
//
//               A) postMessage listener  – catches relays from /auth/relay (same-origin)
//                  or from NVIDIA pages that post messages directly.
//
//               B) location polling      – every 150 ms we try to read popup.location.href.
//                  While the popup is cross-origin (nvidia.com) this throws SecurityError,
//                  which we swallow.  Once NVIDIA redirects to:
//                    • a same-origin URL  (/auth/relay)  → we read it directly
//                    • a custom scheme    (nvapp://)     → Chrome/Firefox may keep the
//                      popup on the previous page OR navigate to the scheme.  In either
//                      case the location read throws, but if the popup navigates to
//                      about:blank after a failed scheme launch we can catch that too.
//                  For custom-scheme redirects the relay page method is more reliable;
//                  use location polling as a belt-and-suspenders fallback.

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
        const popup = window.open(url, "nvidia_login", "width=520,height=680,menubar=no,toolbar=no,location=no");
        if (!popup) {
          reject(new Error("Could not open login popup – please allow popups for this site."));
          return;
        }

        let settled = false;

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

        // ── A) postMessage listener ──────────────────────────────────────────
        // Handles two sources:
        //   • /auth/relay page (sends auth_code)
        //   • server-side /api/auth/callback page (sends auth_success / auth_error)
        const onMessage = async (event: MessageEvent) => {
          if (typeof event.data !== "object" || event.data === null) return;
          const msg = event.data as Record<string, unknown>;

          if (msg.type === "auth_success") {
            // Server already completed token exchange (server-intercept mode)
            settle();
          } else if (msg.type === "auth_error") {
            settle(new Error((msg.error as string) ?? "Authentication failed"));
          } else if (msg.type === "auth_code") {
            // Relay page handed us the raw code – exchange it now
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

        if (interceptMode === "server") {
          // Server-intercept mode: the callback page posts auth_success/error.
          // Location polling is unnecessary; just watch for the popup closing.
        }

        // ── B) location polling (client-intercept / custom-scheme mode) ──────
        // Tries to read popup.location.href every 150 ms.
        // - Cross-origin pages (nvidia.com) → throws SecurityError, we ignore.
        // - Same-origin redirect (/auth/relay) → relay script runs and posts
        //   auth_code back, but we also catch it here for redundancy.
        // - Custom scheme (geforcenow://, nvapp://, etc.) → the browser cannot
        //   navigate to a custom scheme, so it either:
        //     a) briefly makes the href the scheme URL then goes to about:blank, or
        //     b) stays on the last cross-origin page (throws SecurityError) then
        //        goes to about:blank.
        //   In case (b) the scheme URL is NEVER directly readable, so we must
        //   check what caused the about:blank — store the last SecurityError
        //   message, which some browsers include the target URL in.
        //   More reliably: when we land on about:blank we check the document
        //   referrer, which Chrome preserves as the scheme URL.
        let lastReadableHref = "";
        const locationPoll = setInterval(async () => {
          if (settled) return;
          try {
            const href = popup.location.href;
            if (!href) return;

            if (href === "about:blank") {
              // Browser navigated to about:blank after a failed custom-scheme redirect.
              // Try reading document.referrer — Chrome preserves the scheme URL there.
              let referrer = "";
              try { referrer = popup.document.referrer; } catch { /* cross-origin */ }
              const candidateUrl = referrer || lastReadableHref;
              if (candidateUrl && candidateUrl !== "about:blank") {
                const extracted = extractCodeFromUrl(candidateUrl);
                if (extracted) {
                  clearInterval(locationPoll);
                  try {
                    await exchangeCode(extracted.code, extracted.state);
                    settle();
                  } catch (e) {
                    settle(e instanceof Error ? e : new Error(String(e)));
                  }
                }
              }
              return;
            }

            lastReadableHref = href;
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
            // SecurityError expected while popup is on nvidia.com — keep polling
          }
        }, 150);

        // ── C) closed-without-auth guard ─────────────────────────────────────
        const closedPoll = setInterval(() => {
          if (settled) return;
          if (popup.closed) {
            settle(new Error("Login window closed before completing sign-in."));
          }
        }, 500);
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
      console.warn("[shim] getRegions failed:", e);
      return [];
    }
  },

  async fetchSubscription(input) {
    try {
      return await gfnCall("fetchSubscription", input as any);
    } catch (e) {
      console.warn("[shim] fetchSubscription failed:", e);
      return {
        membershipTier: "unknown", allottedHours: 0, purchasedHours: 0,
        rolledOverHours: 0, usedHours: 0, remainingHours: 0, totalHours: 0,
        isUnlimited: false, entitledResolutions: [],
      };
    }
  },

  async fetchMainGames(input) {
    try {
      const data: any = await gfnCall("fetchMainGames", input as any);
      return Array.isArray(data) ? data : (data.apps ?? data.games ?? data.results ?? []);
    } catch (e) {
      console.warn("[shim] fetchMainGames failed:", e);
      return [];
    }
  },

  async fetchStorePanels(input) {
    try {
      const data: any = await gfnCall("fetchStorePanels", input as any);
      return Array.isArray(data) ? data : (data.panels ?? []);
    } catch (e) {
      console.warn("[shim] fetchStorePanels failed:", e);
      return { panels: [], total: 0 };
    }
  },

  async fetchFeaturedGames(input) {
    try {
      const data: any = await gfnCall("fetchFeaturedGames", input as any);
      return Array.isArray(data) ? data : (data.apps ?? data.games ?? data.results ?? []);
    } catch (e) {
      console.warn("[shim] fetchFeaturedGames failed:", e);
      return [];
    }
  },

  async fetchLibraryGames(input) {
    try {
      const data: any = await gfnCall("fetchLibraryGames", input as any);
      return Array.isArray(data) ? data : (data.apps ?? data.games ?? data.results ?? []);
    } catch (e) {
      console.warn("[shim] fetchLibraryGames failed:", e);
      return [];
    }
  },

  async browseCatalog(input) {
    try {
      const data: any = await gfnCall("browseCatalog", input as any);
      if (Array.isArray(data)) return { results: data, total: data.length };
      return {
        results: data.apps ?? data.games ?? data.results ?? [],
        total: data.total ?? data.totalCount ?? 0,
        filterGroups: data.filterGroups ?? data.filters ?? [],
        sortOptions: data.sortOptions ?? data.sorts ?? [],
        supportedCount: data.supportedCount,
      };
    } catch (e) {
      console.warn("[shim] browseCatalog failed:", e);
      return { results: [], total: 0 };
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
