import { useMemo, useSyncExternalStore } from "react";


type TranslationValue = string | number | boolean | null | undefined;
type TranslationValues = Record<string, TranslationValue>;
type TranslationLeaf = string;
type TranslationTree = { [key: string]: TranslationLeaf | TranslationTree };

const FALLBACK_LOCALE = "en";
const LOCALE_STORAGE_KEY = "opennow.locale";

import fallbackTranslationsImport from "../../../locales/en.json";

const localeSources = import.meta.glob<string>("../../../locales/*.json", {
  query: "?raw",
  import: "default",
  eager: true,
});

// Ensure fallback translations are complete for web builds (covers critical UI paths)
const essentialFallbacks: TranslationTree = {
  app: {
    name: "OpenNOW",
    tagline: "Open-source cloud gaming client",
    actions: { add: "Add", back: "Back", browse: "Browse", cancel: "Cancel", close: "Close", confirm: "Confirm", continue: "Continue", delete: "Delete", done: "Done", open: "Open", play: "Play", buy: "Buy", refresh: "Refresh", remove: "Remove", reset: "Reset", resume: "Resume", retry: "Retry", save: "Save", search: "Search", select: "Select", settings: "Settings", stop: "Stop", switch: "Switch" },
    status: { checking: "Checking", connecting: "Connecting...", disabled: "Disabled", error: "Error", failed: "Failed", idle: "Idle", loading: "Loading...", ready: "Ready", saved: "Saved", testing: "Testing...", unknown: "Unknown", upToDate: "Up to date" },
  },
  auth: {
    title: { signIn: "Sign in", restoringSession: "Restoring session" },
    subtitle: { checkingSavedAccounts: "Checking saved accounts." },
    provider: { label: "Provider", select: "Select provider", loading: "Loading..." },
    actions: { signIn: "Sign In", connecting: "Connecting...", restoringSession: "Restoring Session..." },
    status: { restoringSavedSession: "Restoring saved session...", sessionRestoredTokenRefreshed: "Session restored. Token refreshed.", tokenRefreshedLoadingAccount: "Token refreshed. Loading your account...", sessionRestored: "Session restored.", noSavedSessionFound: "No saved session found.", sessionRestoreFailed: "Session restore failed. Please sign in again." },
    accounts: { activeAccount: "Active account", addAccount: "Add account", switchAccount: "Switch account", logOutAll: "Log out all accounts", staySignedIn: "Stay signed in" },
  },
  navigation: { home: "Store", library: "Library", settings: "Settings" },
  home: { searchPlaceholder: "Search games...", filters: "Filters", count: { loading: "Loading...", shown: "{{shown}} shown", shownTotal: "{{shown}} shown · {{total}} total" }, empty: { loadingGames: "Loading games...", noGamesFound: "No games found", tryAdjustingSearch: "Try adjusting your search terms or filters" } },
  library: { title: "My Library", searchPlaceholder: "Search your library...", gameCount: "{{count}} game", gameCount_plural: "{{count}} games", filter: "Filter", allStores: "All Stores", selectedStore: "Selected Store: {{store}}" },
  streamLoading: { labels: { launchError: "Launch error", nowLoading: "Now loading" }, steps: { queue: "Queue", setup: "Setup", ready: "Ready" }, status: { gameLaunchFailed: "Game launch failed", queuePaused: "Session queue paused", positionInQueue: "Position #{{position}} in queue", waitingInQueue: "Waiting in queue...", settingUpRig: "Setting up your gaming rig...", startingStream: "Starting stream...", connectingToServer: "Connecting to server..." }, actions: { cancelLoading: "Cancel loading" } },
  session: { active: "Active session", current: "Current", control: "Session control", elapsed: "Elapsed", endSession: "End session", exitStream: "Exit stream?", resume: "Resume", readyToLaunch: "Ready to launch", timeWarning: "Session time warning", thisGame: "this game" },
  stream: { stats: { connecting: "Connecting...", network: "Network", decode: "Decode", input: "Input", render: "Render", stable: "Stable", roundTripLatency: "Round-trip network latency", packetLoss: "Packet loss percent" }, controls: { antiAfkEnabled: "Anti-AFK enabled", muteMicrophone: "Mute microphone", unmuteMicrophone: "Unmute microphone", enterFullscreen: "Enter fullscreen", exitFullscreen: "Exit fullscreen" }, shortcuts: { clickThenPress: "Click then press a key", examples: "Examples: F3, Ctrl+Shift+Q, Ctrl+Shift+K" } },
  settings: { title: "Settings", saved: "Saved", searchPlaceholder: "Search settings...", noMatches: "No settings matched \"{{query}}\".", sections: { stream: "Stream", game: "Game", audio: "Audio", input: "Input", interface: "Interface", about: "About" }, region: { title: "Region", autoBest: "Auto (best)" }, video: { title: "Video", aspectRatio: "Aspect ratio", resolution: "Resolution", fps: "FPS", codec: "Codec", decoder: "Decoder", encoder: "Encoder", maxBitrate: "Max bitrate" }, game: { title: "Game", language: "Language", keyboardLayout: "Keyboard layout" }, audio: { title: "Audio", microphone: "Microphone", microphoneHint: "Enable voice chat while streaming", microphoneMode: "Microphone mode", disabled: "Disabled", pushToTalk: "Push-to-talk", voiceActivity: "Voice activity" }, input: { title: "Input", mouseAndKeyboard: "Mouse and Keyboard", clipboardPaste: "Clipboard paste", mouseSensitivity: "Mouse sensitivity", mouseAccelerator: "Mouse accelerator", shortcuts: "Shortcuts", toggleStats: "Toggle stats", stopStream: "Stop stream", toggleMicrophone: "Toggle microphone", screenshot: "Screenshot", recording: "Recording" }, interface: { appearance: "Appearance", appLanguage: "App language", accentColor: "Accent color", hideStreamOverlayButtons: "Hide stream overlay buttons", showStatsOnStreamLaunch: "Show stats on stream launch", controllerMode: "Controller mode", discordRichPresence: "Discord rich presence" }, about: { applicationUpdates: "Application updates", version: "Version {{version}}", checkForUpdates: "Check for updates", exportLogs: "Export logs", deleteCache: "Delete cache" } },
  errors: { launchUnknown: "Game could not be launched. Please try again.", launchFailedTitle: "Launch failed", duplicateSessionTitle: "Duplicate session detected", loginFailed: "Login failed", switchAccountFailed: "Switch account failed" },
};

const fallbackTree = Object.assign({}, essentialFallbacks, fallbackTranslationsImport) as TranslationTree;
const loadedLocales = new Map<string, TranslationTree>([[FALLBACK_LOCALE, fallbackTree]]);
const listeners = new Set<() => void>();

let activeLocale = FALLBACK_LOCALE;
let activeTranslations = fallbackTree;
let snapshotVersion = 0;

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function getSnapshot(): number {
  return snapshotVersion;
}

function emitChange(): void {
  snapshotVersion += 1;
  for (const listener of listeners) {
    listener();
  }
}

function localeFromPath(path: string): string | null {
  const fileName = path.split("/").pop();
  if (!fileName?.endsWith(".json")) return null;
  return normalizeLocale(fileName.slice(0, -".json".length));
}

function getLocaleSource(locale: string): string | null {
  const normalized = normalizeLocale(locale);
  for (const [path, source] of Object.entries(localeSources)) {
    if (localeFromPath(path) === normalized) {
      return source;
    }
  }
  return null;
}

function readStoredLocale(): string | null {
  try {
    const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    return stored ? normalizeLocale(stored) : null;
  } catch {
    return null;
  }
}

function writeStoredLocale(locale: string): void {
  try {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
  } catch {
    // Ignore storage failures; locale can still apply for this runtime.
  }
}

function normalizeLocale(locale: string): string {
  const trimmed = locale.trim().toLowerCase().replace("_", "-");
  return trimmed.split("-")[0] || FALLBACK_LOCALE;
}

function getBrowserLocaleCandidates(): string[] {
  const languages = Array.isArray(navigator.languages) && navigator.languages.length > 0
    ? navigator.languages
    : [navigator.language];
  return languages
    .filter((locale): locale is string => typeof locale === "string" && locale.trim().length > 0)
    .map(normalizeLocale);
}

function getInitialLocale(): string {
  return readStoredLocale() ?? getBrowserLocaleCandidates()[0] ?? FALLBACK_LOCALE;
}

function parseLocaleJson(locale: string, raw: string): TranslationTree | null {
  if (raw.trim().length === 0) {
    console.warn(`[i18n] Locale "${locale}" is empty; falling back to English.`);
    return null;
  }

  try {
    return JSON.parse(raw) as TranslationTree;
  } catch (error) {
    console.warn(`[i18n] Failed to parse locale "${locale}"; falling back to English.`, error);
    return null;
  }
}

function loadTranslations(locale: string): TranslationTree | null {
  const normalized = normalizeLocale(locale);
  if (normalized === FALLBACK_LOCALE) return fallbackTree;

  const cached = loadedLocales.get(normalized);
  if (cached) return cached;

  const source = getLocaleSource(normalized);
  if (source === null) return null;

  const parsed = parseLocaleJson(normalized, source);
  if (parsed) {
    loadedLocales.set(normalized, parsed);
  }
  return parsed;
}

function setActiveTranslations(locale: string, translations: TranslationTree | null): void {
  const normalized = normalizeLocale(locale);
  activeLocale = normalized;
  activeTranslations = translations ?? fallbackTree;
  document.documentElement.lang = activeLocale;
  emitChange();
}

function readNestedValue(tree: TranslationTree, key: string): string | null {
  let current: TranslationLeaf | TranslationTree | undefined = tree;
  for (const segment of key.split(".")) {
    if (!current || typeof current !== "object") return null;
    current = current[segment];
  }
  return typeof current === "string" ? current : null;
}

function interpolate(template: string, values: TranslationValues): string {
  return template.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (match, token: string) => {
    const value = values[token];
    return value === undefined || value === null ? match : String(value);
  });
}

function resolvePluralKey(key: string, values: TranslationValues): string {
  return typeof values.count === "number" && values.count !== 1 ? `${key}_plural` : key;
}

export function t(key: string, values: TranslationValues = {}): string {
  const resolvedKey = resolvePluralKey(key, values);
  const translation =
    readNestedValue(activeTranslations, resolvedKey) ??
    readNestedValue(activeTranslations, key) ??
    readNestedValue(fallbackTree, resolvedKey) ??
    readNestedValue(fallbackTree, key);

  if (!translation) {
    if (import.meta.env.DEV) {
      console.warn(`[i18n] Missing translation key "${key}".`);
    }
    return key;
  }

  return interpolate(translation, values);
}

export function getLocale(): string {
  return activeLocale;
}

export function getAvailableLocales(): string[] {
  const locales = new Set<string>([FALLBACK_LOCALE]);
  for (const path of Object.keys(localeSources)) {
    const locale = localeFromPath(path);
    if (locale) locales.add(locale);
  }
  return [...locales].sort();
}

export async function setLocale(locale: string): Promise<void> {
  const normalized = normalizeLocale(locale);
  const translations = loadTranslations(normalized);
  writeStoredLocale(normalized);
  setActiveTranslations(normalized, translations);
}

export async function initializeLocale(): Promise<void> {
  const initialLocale = getInitialLocale();
  const translations = loadTranslations(initialLocale);
  setActiveTranslations(initialLocale, translations);
}

export function useTranslation(): {
  locale: string;
  availableLocales: string[];
  setLocale: (locale: string) => Promise<void>;
  t: typeof t;
} {
  const snapshot = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
  return useMemo(() => ({
    locale: activeLocale,
    availableLocales: getAvailableLocales(),
    setLocale,
    t,
  }), [snapshot]);
}
