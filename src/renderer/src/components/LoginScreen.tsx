import { useState, useRef, useEffect } from "react";
import type { JSX } from "react";
import { LogIn, ChevronDown, Link } from "lucide-react";
import type { LoginProvider } from "@shared/gfn";
import { useTranslation } from "../i18n";
import { OpenNowLogoMark } from "./OpenNowLogoMark";

export interface LoginScreenProps {
  providers: LoginProvider[];
  selectedProviderId: string;
  onProviderChange: (id: string) => void;
  onLogin: () => void;
  isLoading: boolean;
  error: string | null;
  isInitializing?: boolean;
  statusMessage?: string;
}

// Parses code + state out of a localhost:2259 redirect URL.
// Handles both standard URL format and regex fallback for malformed URLs.
function extractCodeFromUrl(href: string): { code: string; state: string } | null {
  try {
    const u = new URL(href);
    const code = u.searchParams.get("code");
    const state = u.searchParams.get("state");
    if (code && state) return { code, state };
  } catch {
    const codeMatch = href.match(/[?&]code=([^&]+)/);
    const stateMatch = href.match(/[?&]state=([^&]+)/);
    if (codeMatch && stateMatch) {
      return {
        code: decodeURIComponent(codeMatch[1]),
        state: decodeURIComponent(stateMatch[1]),
      };
    }
  }
  return null;
}

export function LoginScreen({
  providers,
  selectedProviderId,
  onProviderChange,
  onLogin,
  isLoading,
  error,
  isInitializing = false,
  statusMessage,
}: LoginScreenProps): JSX.Element {
  const { t } = useTranslation();
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // ── Paste-URL modal state (self-contained, no CustomEvent needed) ──────────
  const [pasteModalOpen, setPasteModalOpen] = useState(false);
  const [pasteValue, setPasteValue] = useState("");
  const [pasteError, setPasteError] = useState<string | null>(null);
  const [pasteLoading, setPasteLoading] = useState(false);
  const pasteInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (pasteModalOpen) {
      setPasteValue("");
      setPasteError(null);
      setTimeout(() => pasteInputRef.current?.focus(), 50);
    }
  }, [pasteModalOpen]);

  // Close modal on Escape
  useEffect(() => {
    if (!pasteModalOpen) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") setPasteModalOpen(false);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [pasteModalOpen]);

  async function handlePasteSubmit() {
    setPasteError(null);
    const extracted = extractCodeFromUrl(pasteValue.trim());
    if (!extracted) {
      setPasteError(
        "Couldn't find a code= and state= in that URL. Make sure you copied the full address bar URL."
      );
      return;
    }
    setPasteLoading(true);
    try {
      const res = await fetch("/api/auth/exchange", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: extracted.code, state: extracted.state }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as { error?: string };
        throw new Error(body.error ?? `Server error ${res.status}`);
      }
      // Exchange succeeded — close modal and let App.tsx reload the session
      setPasteModalOpen(false);
      onLogin();
    } catch (e) {
      setPasteError(e instanceof Error ? e.message : "Exchange failed — try again.");
    } finally {
      setPasteLoading(false);
    }
  }

  const selectedProvider = providers.find((p) => p.idpId === selectedProviderId);
  const title = isInitializing ? t("auth.title.restoringSession") : t("auth.title.signIn");
  const subtitle = isInitializing ? t("auth.subtitle.checkingSavedAccounts") : t("app.description");

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleProviderSelect = (providerId: string) => {
    onProviderChange(providerId);
    setIsDropdownOpen(false);
  };

  return (
    <div className="login-screen">
      <div className="login-bg">
        <div className="login-bg-orb login-bg-orb--1" />
        <div className="login-bg-orb login-bg-orb--2" />
        <div className="login-bg-orb login-bg-orb--3" />
        <div className="login-bg-noise" />
      </div>

      <div className="login-content">
        {/* Brand */}
        <div className="login-brand">
          <div className="login-brand-mark">
            <OpenNowLogoMark className="opennow-logo-mark" />
          </div>
          <span className="login-brand-name">OpenNOW</span>
        </div>

        {/* Card */}
        <div className="login-card">
          <div className="login-card-header">
            <h1>{title}</h1>
            <p>{subtitle}</p>
          </div>

          {error && (
            <div className="login-error">
              <span className="login-error-dot" />
              {error}
            </div>
          )}

          {isInitializing && statusMessage && (
            <div className="login-status" role="status" aria-live="polite">
              <span className="login-status-dot" />
              {statusMessage}
            </div>
          )}

          <div className="login-field" ref={dropdownRef}>
            <label className="login-label">{t("auth.provider.label")}</label>
            <button
              className={`login-select ${isDropdownOpen ? "open" : ""}`}
              onClick={() => setIsDropdownOpen(!isDropdownOpen)}
              disabled={isLoading || isInitializing}
              type="button"
            >
              <span className="login-select-text">
                {isInitializing
                  ? t("auth.provider.loading")
                  : selectedProvider?.displayName ?? t("auth.provider.select")}
              </span>
              <ChevronDown
                size={16}
                className={`login-select-chevron ${isDropdownOpen ? "rotated" : ""}`}
              />
            </button>

            {isDropdownOpen && (
              <div className="login-dropdown">
                {providers.map((provider) => (
                  <button
                    key={provider.idpId}
                    className={`login-dropdown-item ${provider.idpId === selectedProviderId ? "selected" : ""}`}
                    onClick={() => handleProviderSelect(provider.idpId)}
                    type="button"
                  >
                    <span>{provider.displayName}</span>
                    {provider.idpId === selectedProviderId && (
                      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M13.78 4.22a.75.75 0 010 1.06l-7.25 7.25a.75.75 0 01-1.06 0L2.22 9.28a.75.75 0 011.06-1.06L6 10.94l6.72-6.72a.75.75 0 011.06 0z" />
                      </svg>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>

          <button
            className={`login-button ${isLoading || isInitializing ? "loading" : ""}`}
            onClick={onLogin}
            disabled={isLoading || isInitializing || !selectedProviderId}
            type="button"
          >
            {isLoading || isInitializing ? (
              <>
                <span className="login-spinner" />
                <span>{isInitializing ? t("auth.actions.restoringSession") : t("auth.actions.connecting")}</span>
              </>
            ) : (
              <>
                <LogIn size={18} />
                <span>{t("auth.actions.signIn")}</span>
              </>
            )}
          </button>

          {/* ── Paste redirect URL button ─────────────────────────────────── */}
          {/* Shown when NVIDIA redirects to localhost:2259 and the popup closes
              without completing auth. The user copies the URL from the popup's
              address bar and pastes it here to finish the exchange manually.  */}
          <button
            type="button"
            onClick={() => setPasteModalOpen(true)}
            disabled={isLoading || isInitializing}
            style={{
              marginTop: "10px",
              width: "100%",
              background: "transparent",
              border: "1px solid rgba(255,255,255,0.12)",
              borderRadius: "8px",
              color: "rgba(255,255,255,0.5)",
              fontSize: "0.8em",
              padding: "8px 12px",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "6px",
              transition: "border-color 0.15s, color 0.15s",
            }}
            onMouseEnter={e => {
              (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(255,255,255,0.3)";
              (e.currentTarget as HTMLButtonElement).style.color = "rgba(255,255,255,0.75)";
            }}
            onMouseLeave={e => {
              (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(255,255,255,0.12)";
              (e.currentTarget as HTMLButtonElement).style.color = "rgba(255,255,255,0.5)";
            }}
          >
            <Link size={13} />
            Signed in but stuck? Paste redirect URL
          </button>
        </div>

        <p className="login-footer">{t("app.tagline")}</p>
      </div>

      {/* ── Paste URL modal ─────────────────────────────────────────────────── */}
      {pasteModalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Paste redirect URL"
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 9999,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          {/* Backdrop */}
          <div
            onClick={() => setPasteModalOpen(false)}
            style={{
              position: "absolute",
              inset: 0,
              background: "rgba(0,0,0,0.65)",
              backdropFilter: "blur(4px)",
            }}
          />

          {/* Card */}
          <div
            style={{
              position: "relative",
              background: "#1a1a2e",
              border: "1px solid rgba(255,255,255,0.12)",
              borderRadius: "14px",
              padding: "28px 28px 24px",
              width: "min(480px, calc(100vw - 32px))",
              boxShadow: "0 24px 64px rgba(0,0,0,0.6)",
            }}
          >
            <div style={{ fontSize: "0.72em", textTransform: "uppercase", letterSpacing: "0.08em", color: "rgba(255,255,255,0.4)", marginBottom: "8px" }}>
              Action required
            </div>
            <h3 style={{ margin: "0 0 10px", fontSize: "1.1em", fontWeight: 600 }}>
              Paste the redirect URL
            </h3>
            <p style={{ margin: "0 0 6px", fontSize: "0.85em", color: "rgba(255,255,255,0.65)", lineHeight: 1.5 }}>
              After signing in, the NVIDIA popup tries to redirect to{" "}
              <code style={{ fontSize: "0.9em", background: "rgba(255,255,255,0.08)", padding: "1px 5px", borderRadius: "4px" }}>localhost:2259</code>{" "}
              which fails on a remote deployment. Copy the full URL from the popup&apos;s address bar and paste it below.
            </p>
            <p style={{ margin: "0 0 16px", fontSize: "0.78em", color: "rgba(255,255,255,0.4)" }}>
              Looks like:{" "}
              <code style={{ wordBreak: "break-all" }}>http://localhost:2259/?state=…&amp;code=…</code>
            </p>

            <input
              ref={pasteInputRef}
              type="text"
              value={pasteValue}
              onChange={e => { setPasteValue(e.target.value); setPasteError(null); }}
              onKeyDown={e => {
                if (e.key === "Enter" && pasteValue.trim() && !pasteLoading) void handlePasteSubmit();
                if (e.key === "Escape") setPasteModalOpen(false);
              }}
              placeholder="http://localhost:2259/?state=…&code=…"
              style={{
                width: "100%",
                boxSizing: "border-box",
                padding: "9px 11px",
                marginBottom: pasteError ? "8px" : "20px",
                borderRadius: "7px",
                border: `1px solid ${pasteError ? "rgba(255,80,80,0.6)" : "rgba(255,255,255,0.15)"}`,
                background: "rgba(255,255,255,0.06)",
                color: "inherit",
                fontSize: "0.82em",
                fontFamily: "monospace",
                outline: "none",
              }}
            />

            {pasteError && (
              <p style={{ margin: "0 0 16px", fontSize: "0.78em", color: "rgba(255,100,100,0.9)", lineHeight: 1.4 }}>
                {pasteError}
              </p>
            )}

            <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
              <button
                type="button"
                onClick={() => setPasteModalOpen(false)}
                disabled={pasteLoading}
                className="logout-confirm-btn logout-confirm-btn-cancel"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handlePasteSubmit()}
                disabled={!pasteValue.trim() || pasteLoading}
                className="logout-confirm-btn logout-confirm-btn-confirm"
              >
                {pasteLoading ? (
                  <><span className="login-spinner" style={{ width: "12px", height: "12px" }} /> Exchanging…</>
                ) : (
                  "Complete sign-in"
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
