import { useEffect, useRef, useState, type ReactNode } from "react";
import { label as humanize, statusTone, toneColor, type Tone } from "../lib/format";
import { Sparkline } from "./Charts";

export function Panel({
  title,
  subtitle,
  action,
  children,
  flush = false,
  tight = false
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  tight?: boolean;
}) {
  return (
    <section className="panel">
      <header>
        <div>
          <h2>{title}</h2>
          {subtitle && <p className="panel-sub">{subtitle}</p>}
        </div>
        {action && <div className="panel-action">{action}</div>}
      </header>
      <div className={`panel-body${flush ? " flush" : ""}${tight ? " tight" : ""}`}>{children}</div>
    </section>
  );
}

export function Badge({ value, tone }: { value?: string; tone?: Tone }) {
  return <span className={`badge ${tone ?? statusTone(value)}`}>{humanize(value ?? "Unknown")}</span>;
}

export function Metric({
  label,
  value,
  detail,
  tone = "info",
  spark,
  icon
}: {
  label: string;
  value: string | number;
  detail?: string;
  tone?: Tone;
  spark?: number[];
  icon?: ReactNode;
}) {
  const color = toneColor(tone);
  return (
    <article className="metric" style={{ ["--metric-tone" as string]: color }}>
      <div className="metric-label">
        {icon}
        {label}
      </div>
      <div className="metric-value">{typeof value === "number" ? <AnimatedNumber value={value} /> : value}</div>
      {detail && <div className="metric-detail">{detail}</div>}
      {spark && spark.length > 1 && (
        <div className="metric-spark">
          <Sparkline values={spark} color={color} />
        </div>
      )}
    </article>
  );
}

/**
 * Counts toward the new value so refreshed metrics read as movement rather than a jump. Animation frames do not
 * fire while a tab is hidden, so the tween is skipped there and backed by a timer that snaps to the final value —
 * a metric must never be left showing a stale number.
 */
export function AnimatedNumber({ value, decimals = 0 }: { value: number; decimals?: number }) {
  const [shown, setShown] = useState(value);
  const previous = useRef(value);
  useEffect(() => {
    const from = previous.current;
    previous.current = value;
    if (from === value) return;
    if (typeof document !== "undefined" && document.hidden) {
      setShown(value);
      return;
    }
    const started = performance.now();
    const duration = 420;
    let frame = 0;
    const step = (now: number) => {
      const progress = Math.min(1, (now - started) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      setShown(from + (value - from) * eased);
      if (progress < 1) frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    const settle = window.setTimeout(() => setShown(value), duration + 150);
    return () => {
      cancelAnimationFrame(frame);
      window.clearTimeout(settle);
    };
  }, [value]);
  return <>{shown.toFixed(decimals)}</>;
}

export function EmptyState({ title, detail, icon }: { title: string; detail: string; icon?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-icon">{icon ?? <Icon name="inbox" />}</div>
      <h3>{title}</h3>
      <p>{detail}</p>
    </div>
  );
}

export function KV({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div>
      <dt>{k}</dt>
      <dd>{v}</dd>
    </div>
  );
}

export function Segmented<T extends string>({
  options,
  value,
  onChange
}: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (next: T) => void;
}) {
  return (
    <div className="segmented" role="tablist">
      {options.map((option) => (
        <button
          key={option.value}
          role="tab"
          aria-selected={value === option.value}
          className={value === option.value ? "active" : ""}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Tabs<T extends string>({
  options,
  value,
  onChange
}: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (next: T) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {options.map((option) => (
        <button key={option.value} role="tab" aria-selected={value === option.value} className={value === option.value ? "active" : ""} onClick={() => onChange(option.value)}>
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Switch({ checked, onChange, label: caption }: { checked: boolean; onChange: (next: boolean) => void; label?: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={caption}
      className={`switch${checked ? " on" : ""}`}
      onClick={() => onChange(!checked)}
    />
  );
}

export function Slider({
  label: caption,
  value,
  min,
  max,
  step,
  format,
  onChange
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  format: (value: number) => string;
  onChange: (next: number) => void;
}) {
  const fill = ((value - min) / (max - min)) * 100;
  return (
    <div className="slider-row">
      <header>
        <span>{caption}</span>
        <strong>{format(value)}</strong>
      </header>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        style={{ ["--fill" as string]: `${fill}%` }}
        onChange={(event) => onChange(Number(event.target.value))}
      />
    </div>
  );
}

export function RiskBar({ risk }: { risk: number }) {
  const tone = risk >= 0.81 ? "danger" : risk >= 0.5 ? "warning" : risk >= 0.2 ? "info" : "success";
  return (
    <div className="risk-cell">
      <div className="risk-track">
        <div className="risk-fill" style={{ width: `${Math.max(2, Math.min(100, risk * 100))}%`, background: toneColor(tone) }} />
      </div>
      <span className="risk-value tabular">{(risk * 100).toFixed(1)}%</span>
    </div>
  );
}

export function MethodTag({ method }: { method?: string }) {
  const value = (method ?? "?").toUpperCase();
  return <span className={`method-tag ${value}`}>{value}</span>;
}

export function CodeBlock({ value }: { value: unknown }) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return <pre className="code-block">{text}</pre>;
}

export function Skeleton({ height = 16, width = "100%" }: { height?: number | string; width?: number | string }) {
  return <div className="skeleton" style={{ height, width }} />;
}

/* ------------------------------------------------------------------ *
 * Toasts
 * ------------------------------------------------------------------ */
export type Toast = { id: number; title: string; detail?: string; tone: Tone };

export function ToastLayer({ toasts }: { toasts: Toast[] }) {
  return (
    <div className="toast-layer">
      {toasts.map((toast) => (
        <div className="toast" key={toast.id}>
          <span className={`dot ${toast.tone}`} />
          <p>
            <strong>{toast.title}</strong>
            {toast.detail}
          </p>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Icons — single stroke set so the shell stays visually consistent
 * ------------------------------------------------------------------ */
const PATHS: Record<string, ReactNode> = {
  overview: <><rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" /></>,
  live: <><path d="M12 2v4" /><path d="M12 18v4" /><path d="M4.9 4.9l2.9 2.9" /><path d="M16.2 16.2l2.9 2.9" /><path d="M2 12h4" /><path d="M18 12h4" /><path d="M4.9 19.1l2.9-2.9" /><path d="M16.2 7.8l2.9-2.9" /></>,
  requests: <><path d="M4 6h16" /><path d="M4 12h16" /><path d="M4 18h10" /></>,
  flow: <><circle cx="5" cy="12" r="2.5" /><circle cx="19" cy="6" r="2.5" /><circle cx="19" cy="18" r="2.5" /><path d="M7.5 11l9-4" /><path d="M7.5 13l9 4" /></>,
  models: <><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" /><path d="M12 12l8-4.5" /><path d="M12 12v9" /><path d="M12 12L4 7.5" /></>,
  training: <><path d="M3 17l5-5 4 3 8-8" /><path d="M16 7h4v4" /></>,
  policy: <><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z" /><path d="M9 12l2 2 4-4" /></>,
  block: <><circle cx="12" cy="12" r="9" /><path d="M5.6 5.6l12.8 12.8" /></>,
  network: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18" /><path d="M12 3a14 14 0 010 18a14 14 0 010-18z" /></>,
  apps: <><rect x="3" y="4" width="18" height="7" rx="1.5" /><rect x="3" y="14" width="18" height="6" rx="1.5" /><path d="M7 7.5h.01" /><path d="M7 17h.01" /></>,
  feedback: <><path d="M21 11.5a8.4 8.4 0 01-9 8.4L3 21l1.1-4.4A8.4 8.4 0 1121 11.5z" /></>,
  health: <><path d="M3 12h4l2.5-6 4 12 2.5-6h5" /></>,
  audit: <><path d="M14 3v5h5" /><path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V8l-6-5z" /><path d="M9 13h6" /><path d="M9 17h4" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.6 1.6 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.6 1.6 0 00-2.7 1.1V21a2 2 0 11-4 0v-.1A1.6 1.6 0 007.5 19l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.6 1.6 0 00-1.1-2.7H3a2 2 0 110-4h.1A1.6 1.6 0 004.6 7.5l-.1-.1a2 2 0 112.8-2.8l.1.1a1.6 1.6 0 002.7-1.1V3a2 2 0 114 0v.1a1.6 1.6 0 002.7 1.1l.1-.1a2 2 0 112.8 2.8l-.1.1a1.6 1.6 0 001.1 2.7H21a2 2 0 110 4h-.1a1.6 1.6 0 00-1.5 1.3z" /></>,
  search: <><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" /></>,
  refresh: <><path d="M20 11a8 8 0 10-2.3 6.2" /><path d="M20 5v6h-6" /></>,
  inbox: <><path d="M3 12h5l2 3h4l2-3h5" /><path d="M5 5h14l2 7v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6l2-7z" /></>,
  shield: <><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z" /></>,
  bolt: <><path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  target: <><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1.4" /></>,
  globe: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18" /><path d="M12 3a14 14 0 010 18a14 14 0 010-18z" /></>,
  play: <><path d="M6 4l14 8-14 8V4z" /></>,
  send: <><path d="M21 3L10.5 13.5" /><path d="M21 3l-7 18-3.5-7.5L3 10l18-7z" /></>,
  check: <><path d="M4 12.5l5 5L20 6.5" /></>,
  alert: <><path d="M12 3l9.5 17h-19L12 3z" /><path d="M12 9v5" /><path d="M12 17.5h.01" /></>,
  layers: <><path d="M12 3l9 5-9 5-9-5 9-5z" /><path d="M3 13l9 5 9-5" /></>,
  activity: <><path d="M3 12h4l2.5-6 4 12 2.5-6h5" /></>
};

export function Icon({ name, size = 15 }: { name: keyof typeof PATHS | string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {PATHS[name] ?? PATHS.inbox}
    </svg>
  );
}

/** Downward triangle mark used in the sidebar and on the sign-in card. Deliberately unlabelled. */
export function Mark({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={(size * 65) / 76} viewBox="0 0 76 65" fill="currentColor" aria-hidden="true">
      <path d="M0 0h75.2L37.6 65z" />
    </svg>
  );
}
