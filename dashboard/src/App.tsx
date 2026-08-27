import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { ApiError, DashboardApi, type DashboardSnapshot, type EventRecord } from "./api";
import { Icon, Mark, ToastLayer, type Toast } from "./components/Ui";
import { formatTime, isDetection, type Tone } from "./lib/format";
import { useEventStream } from "./lib/useEventStream";
import type { Section, ViewProps } from "./lib/view";
import { Overview } from "./pages/Overview";
import { LiveAttacks } from "./pages/LiveAttacks";
import { Requests } from "./pages/Requests";
import { Visualizer } from "./pages/Visualizer";
import { Escalations } from "./pages/Escalations";
import { Generator } from "./pages/Generator";
import { Models } from "./pages/Models";
import { Training } from "./pages/Training";
import { PolicyPage } from "./pages/Policy";
import { AccessControl } from "./pages/AccessControl";
import { Applications } from "./pages/Applications";
import { NetworkPage } from "./pages/Network";
import { Review } from "./pages/Review";
import { Services } from "./pages/Services";
import { AuditPage } from "./pages/Audit";
import { SettingsPage } from "./pages/Settings";

type Credentials = { username: string; password: string };

const NAV: [string, { section: Section; icon: string }[]][] = [
  ["Observe", [
    { section: "Overview", icon: "overview" },
    { section: "Live Attacks", icon: "live" },
    { section: "Requests", icon: "requests" },
    { section: "Request Visualizer", icon: "flow" },
    { section: "Escalations", icon: "layers" }
  ]],
  ["Intelligence", [
    { section: "Models", icon: "models" },
    { section: "Generator", icon: "play" },
    { section: "Training", icon: "training" }
  ]],
  ["Enforce", [
    { section: "Policy", icon: "policy" },
    { section: "Access Control", icon: "block" },
    { section: "Applications", icon: "apps" },
    { section: "Network", icon: "network" }
  ]],
  ["Operate", [
    { section: "Review", icon: "feedback" },
    { section: "Services", icon: "health" },
    { section: "Audit", icon: "audit" },
    { section: "Settings", icon: "settings" }
  ]]
];

const MAX_LIVE_EVENTS = 400;

export function App() {
  const [section, setSection] = useState<Section>("Overview");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [credentials, setCredentials] = useState<Credentials>();
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>();
  const [selected, setSelected] = useState<EventRecord>();
  const [loading, setLoading] = useState(false);
  const [signingIn, setSigningIn] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [lastRefresh, setLastRefresh] = useState<Date>();
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [streamEnabled, setStreamEnabled] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(15);
  const [liveIds, setLiveIds] = useState<Set<string>>(new Set());
  const toastId = useRef(0);

  const api = useMemo(
    () => (credentials ? new DashboardApi(credentials.username, credentials.password) : undefined),
    [credentials]
  );

  const notify = useCallback((title: string, detail?: string, tone: Tone = "success") => {
    const id = (toastId.current += 1);
    setToasts((current) => [...current, { id, title, detail, tone }]);
    window.setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), 4200);
  }, []);

  const applySnapshot = useCallback((next: DashboardSnapshot) => {
    setSnapshot(next);
    setSelected((current) => next.events.find((event) => event.eventId === current?.eventId) ?? current ?? next.events[0]);
    setLastRefresh(new Date());
  }, []);

  const refresh = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    try {
      applySnapshot(await api.snapshot());
    } catch (error) {
      notify(
        error instanceof ApiError && error.status === 401 ? "Session expired" : "Refresh failed",
        error instanceof Error ? error.message : "unknown error",
        "danger"
      );
    } finally {
      setLoading(false);
    }
  }, [api, applySnapshot, notify]);

  /** A streamed event is merged into the retained window immediately; statistics catch up on the next poll. */
  const onStreamedEvent = useCallback((event: EventRecord) => {
    setSnapshot((current) => {
      if (!current) return current;
      if (current.events.some((existing) => existing.eventId === event.eventId)) return current;
      return { ...current, events: [event, ...current.events].slice(0, MAX_LIVE_EVENTS) };
    });
    setLiveIds((current) => {
      const next = new Set(current);
      next.add(event.eventId);
      return next;
    });
    window.setTimeout(() => setLiveIds((current) => {
      const next = new Set(current);
      next.delete(event.eventId);
      return next;
    }), 2000);
  }, []);

  const stream = useEventStream({ api, enabled: streamEnabled && Boolean(credentials), onEvent: onStreamedEvent });

  useEffect(() => {
    if (!api || refreshInterval <= 0) return;
    const timer = window.setInterval(() => void refresh(), refreshInterval * 1000);
    return () => window.clearInterval(timer);
  }, [api, refresh, refreshInterval]);

  const signIn = async (event: FormEvent) => {
    event.preventDefault();
    setSigningIn(true);
    setLoginError("");
    try {
      const candidate = new DashboardApi(username.trim(), password);
      const next = await candidate.snapshot();
      setCredentials({ username: username.trim(), password });
      applySnapshot(next);
    } catch (error) {
      setLoginError(
        error instanceof ApiError && error.status === 401
          ? "Incorrect username or password."
          : `Unavailable: ${error instanceof Error ? error.message : "unknown error"}`
      );
    } finally {
      setSigningIn(false);
    }
  };

  const mutate = useCallback(async (action: () => Promise<unknown>, success: string) => {
    try {
      await action();
      notify(success);
      await refresh();
    } catch (error) {
      notify("Action failed", error instanceof Error ? error.message : "unknown error", "danger");
    }
  }, [notify, refresh]);

  const signOut = () => {
    setCredentials(undefined);
    setSnapshot(undefined);
    setSelected(undefined);
    setPassword("");
    setSection("Overview");
    setLoginError("");
  };

  if (!credentials || !snapshot || !api) {
    return (
      <SignIn
        username={username}
        password={password}
        loading={signingIn}
        error={loginError}
        onUsername={setUsername}
        onPassword={setPassword}
        onSubmit={signIn}
        onFillDemo={() => { setUsername("admin"); setPassword("adaptive_waf_dev"); setLoginError(""); }}
      />
    );
  }

  const detections = snapshot.events.filter(isDetection).length;
  const props: ViewProps = {
    snapshot,
    selected,
    select: setSelected,
    api,
    mutate,
    notify,
    refresh,
    username: credentials.username,
    goTo: setSection,
    signOut,
    stream,
    streamEnabled,
    setStreamEnabled,
    refreshInterval,
    setRefreshInterval,
    liveIds
  };

  const streamTone = stream.state === "live" ? "success" : stream.state === "offline" ? "neutral" : "warning";

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="sidebar-brand"><Mark size={20} /></div>
        <nav className="sidebar-nav">
          {NAV.map(([group, entries]) => (
            <div className="nav-group" key={group}>
              <p>{group}</p>
              {entries.map((entry) => (
                <button
                  key={entry.section}
                  className={section === entry.section ? "nav-item active" : "nav-item"}
                  onClick={() => setSection(entry.section)}
                >
                  <Icon name={entry.icon} size={14} />
                  {entry.section}
                  {entry.section === "Live Attacks" && detections > 0 && <span className="nav-count">{detections}</span>}
                  {entry.section === "Requests" && <span className="nav-count">{snapshot.events.length}</span>}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="stream-pill">
            <span className={`dot ${streamTone}${stream.state === "live" ? " live" : ""}`} />
            <strong>{stream.state === "live" ? "Streaming" : stream.state === "retrying" ? "Reconnecting" : stream.state === "connecting" ? "Connecting" : "Polling"}</strong>
            <span className="count">{stream.received}</span>
          </div>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Security</span>
            <i>/</i>
            <strong>{section}</strong>
          </div>
          <div className="topbar-actions">
            <span className="topbar-meta">{lastRefresh ? `Synced ${formatTime(lastRefresh)}` : "Connecting"}</span>
            <button className="btn small" onClick={() => void refresh()} disabled={loading}>
              {loading ? <span className="spinner" /> : <Icon name="refresh" size={13} />}
              {loading ? "Syncing" : "Refresh"}
            </button>
            <button className="user-chip" onClick={() => setSection("Settings")}>
              <span>{credentials.username.slice(0, 1).toUpperCase()}</span>
              {credentials.username}
            </button>
          </div>
        </header>

        <div className="page" key={section}>
          <div className="page-header animate-up">
            <h1>{section}</h1>
          </div>
          <div className="animate-up" style={{ animationDelay: "0.05s" }}>{renderSection(section, props)}</div>
        </div>
      </main>

      <ToastLayer toasts={toasts} />
    </div>
  );
}

function renderSection(section: Section, props: ViewProps) {
  switch (section) {
    case "Overview": return <Overview {...props} />;
    case "Live Attacks": return <LiveAttacks {...props} />;
    case "Requests": return <Requests {...props} />;
    case "Request Visualizer": return <Visualizer {...props} />;
    case "Escalations": return <Escalations {...props} />;
    case "Generator": return <Generator {...props} />;
    case "Models": return <Models {...props} />;
    case "Training": return <Training {...props} />;
    case "Policy": return <PolicyPage {...props} />;
    case "Access Control": return <AccessControl {...props} />;
    case "Applications": return <Applications {...props} />;
    case "Network": return <NetworkPage {...props} />;
    case "Review": return <Review {...props} />;
    case "Services": return <Services {...props} />;
    case "Audit": return <AuditPage {...props} />;
    case "Settings": return <SettingsPage {...props} />;
  }
}

function SignIn({
  username,
  password,
  loading,
  error,
  onUsername,
  onPassword,
  onSubmit,
  onFillDemo
}: {
  username: string;
  password: string;
  loading: boolean;
  error: string;
  onUsername: (value: string) => void;
  onPassword: (value: string) => void;
  onSubmit: (event: FormEvent) => void;
  onFillDemo: () => void;
}) {
  return (
    <main className="auth-shell">
      <div className="auth-aurora" aria-hidden="true" />
      <div className="auth-grid" aria-hidden="true" />
      <section className="auth-card">
        <div className="auth-mark"><Mark size={30} /></div>
        <h1>Sign in</h1>
        <form onSubmit={onSubmit}>
          <label>
            Username
            <input autoFocus autoComplete="username" value={username} onChange={(event) => onUsername(event.target.value)} />
          </label>
          <label>
            Password
            <input type="password" autoComplete="current-password" value={password} onChange={(event) => onPassword(event.target.value)} />
          </label>
          {error && <div className="auth-error" role="alert"><Icon name="alert" size={14} />{error}</div>}
          <button className="auth-submit" disabled={loading || !username.trim() || !password}>
            {loading ? "Connecting…" : "Continue"}
          </button>
        </form>
        <div className="auth-secondary">
          <button type="button" className="link-btn" onClick={onFillDemo}>Use local credentials</button>
        </div>
      </section>
      <footer className="auth-footer">Local environment</footer>
    </main>
  );
}
