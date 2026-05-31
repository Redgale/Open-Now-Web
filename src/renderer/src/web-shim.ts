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

function openLoginPopup(provider: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const url = `/api/auth/login?provider=${encodeURIComponent(provider)}`;
    const popup = window.open(url, "nvidia_login", "width=520,height=680,menubar=no,toolbar=no");
    if (!popup) {
      reject(new Error("Could not open login popup – please allow popups for this site."));
      return;
    }
    const timer = setInterval(() => {
      if (popup.closed) {
        clearInterval(timer);
        reject(new Error("Login window closed before completing sign-in."));
      }
    }, 500);

    const handleMessage = (event: MessageEvent) => {
      if (typeof event.data !== "object" || event.data === null) return;
      const { type, error } = event.data as { type: string; error?: string };
      if (type === "auth_success") {
        clearInterval(timer);
        window.removeEventListener("message", handleMessage);
        popup.close();
        resolve();
      } else if (type === "auth_error") {
        clearInterval(timer);
        window.removeEventListener("message", handleMessage);
        popup.close();
        reject(new Error(error ?? "Authentication failed"));
      }
    };
    window.addEventListener("message", handleMessage);
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
