import { useId, useMemo, useState, type ReactNode } from "react";
import { colorFor, compactNumber } from "../lib/format";

type Point = { label: string; value: number };
type Series = { name: string; color: string; values: number[] };

function useTooltip() {
  const [tip, setTip] = useState<{ x: number; y: number; node: ReactNode } | undefined>();
  const holder = tip ? (
    <div className="chart-tooltip" style={{ left: tip.x, top: tip.y }}>{tip.node}</div>
  ) : null;
  return { tip, setTip, holder };
}

/* ------------------------------------------------------------------ *
 * Sparkline
 * ------------------------------------------------------------------ */
export function Sparkline({ values, color = "#3b82f6", height = 30 }: { values: number[]; color?: string; height?: number }) {
  const gradientId = useId();
  if (values.length < 2) return <svg className="chart" height={height} />;
  const width = 100;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const points = values.map((value, index) => {
    const x = (index / (values.length - 1)) * width;
    const y = height - 2 - ((value - min) / span) * (height - 6);
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });
  return (
    <svg className="chart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" height={height}>
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.28" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={`0,${height} ${points.join(" ")} ${width},${height}`} fill={`url(#${gradientId})`} />
      <polyline className="series-line" points={points.join(" ")} stroke={color} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/* ------------------------------------------------------------------ *
 * Stacked area / line timeline
 * ------------------------------------------------------------------ */
export function AreaChart({
  labels,
  series,
  height = 200,
  yFormat = compactNumber
}: {
  labels: string[];
  series: Series[];
  height?: number;
  yFormat?: (value: number) => string;
}) {
  const gradientId = useId();
  const { setTip, holder } = useTooltip();
  const padding = { top: 14, right: 12, bottom: 24, left: 40 };
  const width = 720;
  const innerWidth = width - padding.left - padding.right;
  const innerHeight = height - padding.top - padding.bottom;
  const max = Math.max(1, ...series.flatMap((entry) => entry.values));
  const ticks = useMemo(() => [0, 0.25, 0.5, 0.75, 1].map((step) => Math.round(max * step)), [max]);

  if (!labels.length) return <Empty height={height} message="No samples in the retained window" />;

  const xFor = (index: number) => padding.left + (labels.length === 1 ? innerWidth / 2 : (index / (labels.length - 1)) * innerWidth);
  const yFor = (value: number) => padding.top + innerHeight - (value / max) * innerHeight;

  return (
    <div className="chart-holder">
      <svg className="chart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style={{ height }}>
        <defs>
          {series.map((entry, index) => (
            <linearGradient key={entry.name} id={`${gradientId}-${index}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={entry.color} stopOpacity="0.3" />
              <stop offset="100%" stopColor={entry.color} stopOpacity="0" />
            </linearGradient>
          ))}
        </defs>
        {ticks.map((tick) => (
          <g key={tick}>
            <line className="grid-line" x1={padding.left} x2={width - padding.right} y1={yFor(tick)} y2={yFor(tick)} />
            <text className="axis-text" x={padding.left - 8} y={yFor(tick) + 3} textAnchor="end">{yFormat(tick)}</text>
          </g>
        ))}
        {series.map((entry, index) => {
          const path = entry.values.map((value, position) => `${position === 0 ? "M" : "L"}${xFor(position)},${yFor(value)}`).join(" ");
          const area = `${path} L${xFor(entry.values.length - 1)},${yFor(0)} L${xFor(0)},${yFor(0)} Z`;
          return (
            <g key={entry.name}>
              <path d={area} fill={`url(#${gradientId}-${index})`} />
              <path className="series-line" d={path} stroke={entry.color} vectorEffect="non-scaling-stroke" />
            </g>
          );
        })}
        {labels.map((tickLabel, index) =>
          index % Math.max(1, Math.ceil(labels.length / 8)) === 0 ? (
            <text key={tickLabel + index} className="axis-text" x={xFor(index)} y={height - 6} textAnchor="middle">
              {tickLabel}
            </text>
          ) : null
        )}
        {labels.map((tickLabel, index) => (
          <rect
            key={`hit-${index}`}
            x={xFor(index) - innerWidth / labels.length / 2}
            y={padding.top}
            width={innerWidth / labels.length}
            height={innerHeight}
            fill="transparent"
            onMouseEnter={(event) => {
              const bounds = event.currentTarget.ownerSVGElement!.getBoundingClientRect();
              setTip({
                x: ((xFor(index) / width) * bounds.width),
                y: (padding.top / height) * bounds.height + 10,
                node: (
                  <>
                    <strong>{tickLabel}</strong>
                    {series.map((entry) => (
                      <span key={entry.name} style={{ display: "block", color: entry.color }}>
                        {entry.name} · {entry.values[index] ?? 0}
                      </span>
                    ))}
                  </>
                )
              });
            }}
            onMouseLeave={() => setTip(undefined)}
          />
        ))}
      </svg>
      {holder}
      <Legend series={series} />
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Grouped bar chart — used for model comparison
 * ------------------------------------------------------------------ */
export function GroupedBarChart({
  groups,
  series,
  height = 240,
  format = (value: number) => value.toFixed(3),
  domainMax
}: {
  groups: string[];
  series: Series[];
  height?: number;
  format?: (value: number) => string;
  domainMax?: number;
}) {
  const { setTip, holder } = useTooltip();
  const padding = { top: 14, right: 12, bottom: 34, left: 46 };
  const width = 720;
  const innerWidth = width - padding.left - padding.right;
  const innerHeight = height - padding.top - padding.bottom;
  const max = domainMax ?? Math.max(0.0001, ...series.flatMap((entry) => entry.values));

  if (!groups.length || !series.length) return <Empty height={height} message="No comparable metrics were recorded" />;

  const groupWidth = innerWidth / groups.length;
  const barWidth = Math.max(4, (groupWidth * 0.72) / series.length);

  return (
    <div className="chart-holder">
      <svg className="chart" viewBox={`0 0 ${width} ${height}`} style={{ height }}>
        {[0, 0.25, 0.5, 0.75, 1].map((step) => {
          const y = padding.top + innerHeight - step * innerHeight;
          return (
            <g key={step}>
              <line className="grid-line" x1={padding.left} x2={width - padding.right} y1={y} y2={y} />
              <text className="axis-text" x={padding.left - 8} y={y + 3} textAnchor="end">{format(max * step)}</text>
            </g>
          );
        })}
        {groups.map((group, groupIndex) => (
          <g key={group}>
            {series.map((entry, seriesIndex) => {
              const value = entry.values[groupIndex] ?? 0;
              const barHeight = Math.max(1, (value / max) * innerHeight);
              const x = padding.left + groupIndex * groupWidth + groupWidth * 0.14 + seriesIndex * barWidth;
              return (
                <rect
                  key={entry.name}
                  className="bar-rect"
                  x={x}
                  y={padding.top + innerHeight - barHeight}
                  width={barWidth - 2}
                  height={barHeight}
                  rx={2}
                  fill={entry.color}
                  onMouseEnter={(event) => {
                    const bounds = event.currentTarget.ownerSVGElement!.getBoundingClientRect();
                    setTip({
                      x: ((x + barWidth / 2) / width) * bounds.width,
                      y: ((padding.top + innerHeight - barHeight) / height) * bounds.height,
                      node: (
                        <>
                          <strong>{entry.name}</strong>
                          <span>{group} · {format(value)}</span>
                        </>
                      )
                    });
                  }}
                  onMouseLeave={() => setTip(undefined)}
                />
              );
            })}
            <text className="axis-text" x={padding.left + groupIndex * groupWidth + groupWidth / 2} y={height - 14} textAnchor="middle">
              {group.length > 14 ? `${group.slice(0, 13)}…` : group}
            </text>
          </g>
        ))}
      </svg>
      {holder}
      <Legend series={series} />
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Donut
 * ------------------------------------------------------------------ */
export function DonutChart({ data, size = 152, centerLabel }: { data: Point[]; size?: number; centerLabel?: string }) {
  const total = data.reduce((sum, entry) => sum + entry.value, 0);
  const [active, setActive] = useState<number>();
  if (!total) return <Empty height={size} message="Nothing recorded yet" />;
  const radius = size / 2 - 10;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="donut-wrap">
      <svg className="chart" width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ width: size, flex: "0 0 auto" }}>
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          {data.map((entry, index) => {
            const fraction = entry.value / total;
            const dash = fraction * circumference;
            const element = (
              <circle
                key={entry.label}
                cx={size / 2}
                cy={size / 2}
                r={radius}
                fill="none"
                stroke={colorFor(entry.label, index)}
                strokeWidth={active === index ? 20 : 15}
                strokeDasharray={`${dash} ${circumference - dash}`}
                strokeDashoffset={-offset}
                style={{ transition: "stroke-width 0.2s cubic-bezier(0.22,1,0.36,1)", cursor: "pointer" }}
                onMouseEnter={() => setActive(index)}
                onMouseLeave={() => setActive(undefined)}
              />
            );
            offset += dash;
            return element;
          })}
        </g>
        <text className="donut-center" x={size / 2} y={size / 2 - 3} textAnchor="middle" fill="#ededed" fontSize="21" fontWeight="600">
          {active === undefined ? total : data[active].value}
        </text>
        <text className="donut-center" x={size / 2} y={size / 2 + 14} textAnchor="middle" fill="#6e6e6e" fontSize="10">
          {active === undefined ? centerLabel ?? "total" : `${((data[active].value / total) * 100).toFixed(1)}%`}
        </text>
      </svg>
      <div className="donut-legend">
        {data.map((entry, index) => (
          <div
            key={entry.label}
            className="donut-legend-row"
            onMouseEnter={() => setActive(index)}
            onMouseLeave={() => setActive(undefined)}
            style={{ opacity: active === undefined || active === index ? 1 : 0.5, transition: "opacity 0.16s" }}
          >
            <i style={{ background: colorFor(entry.label, index) }} />
            <span className="name">{entry.label}</span>
            <span className="value">{entry.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Horizontal ranked bars
 * ------------------------------------------------------------------ */
export function RankedBars({
  data,
  format = (value: number) => String(value),
  colorKey
}: {
  data: Point[];
  format?: (value: number) => string;
  colorKey?: (label: string, index: number) => string;
}) {
  if (!data.length) return <Empty height={120} message="No entries recorded" />;
  const max = Math.max(...data.map((entry) => entry.value), 1);
  return (
    <div className="hbar-list">
      {data.map((entry, index) => (
        <div className="hbar" key={entry.label}>
          <div className="hbar-head">
            <span className="label" title={entry.label}>{entry.label}</span>
            <span className="value">{format(entry.value)}</span>
          </div>
          <div className="hbar-track">
            <div
              className="hbar-fill"
              style={{
                width: `${(entry.value / max) * 100}%`,
                background: (colorKey ?? colorFor)(entry.label, index),
                animationDelay: `${index * 0.03}s`
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Radial gauge
 * ------------------------------------------------------------------ */
export function RadialGauge({ value, label: caption, color = "#3b82f6", size = 116 }: { value: number; label: string; color?: string; size?: number }) {
  const radius = size / 2 - 9;
  const circumference = Math.PI * radius * 1.5;
  const clamped = Math.max(0, Math.min(1, value));
  return (
    <svg className="chart" width={size} height={size * 0.78} viewBox={`0 0 ${size} ${size * 0.78}`} style={{ width: size }}>
      <g transform={`rotate(135 ${size / 2} ${size / 2})`}>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#1c1c1c" strokeWidth="8"
          strokeDasharray={`${circumference} ${circumference * 3}`} strokeLinecap="round" />
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={`${circumference * clamped} ${circumference * 3}`} strokeLinecap="round"
          style={{ transition: "stroke-dasharray 0.7s cubic-bezier(0.22,1,0.36,1)" }} />
      </g>
      <text x={size / 2} y={size / 2 + 2} textAnchor="middle" fill="#ededed" fontSize="19" fontWeight="600">
        {(clamped * 100).toFixed(0)}%
      </text>
      <text x={size / 2} y={size / 2 + 18} textAnchor="middle" fill="#6e6e6e" fontSize="9.5">{caption}</text>
    </svg>
  );
}

/* ------------------------------------------------------------------ *
 * Scatter — risk against latency
 * ------------------------------------------------------------------ */
export function ScatterChart({
  points,
  height = 220,
  xLabel,
  yLabel
}: {
  points: { x: number; y: number; label: string; color: string }[];
  height?: number;
  xLabel: string;
  yLabel: string;
}) {
  const { setTip, holder } = useTooltip();
  const padding = { top: 14, right: 16, bottom: 32, left: 46 };
  const width = 720;
  const innerWidth = width - padding.left - padding.right;
  const innerHeight = height - padding.top - padding.bottom;
  if (!points.length) return <Empty height={height} message="No requests with recorded latency" />;
  const maxX = Math.max(...points.map((point) => point.x), 1);

  return (
    <div className="chart-holder">
      <svg className="chart" viewBox={`0 0 ${width} ${height}`} style={{ height }}>
        {[0, 0.25, 0.5, 0.75, 1].map((step) => {
          const y = padding.top + innerHeight - step * innerHeight;
          return (
            <g key={step}>
              <line className="grid-line" x1={padding.left} x2={width - padding.right} y1={y} y2={y} />
              <text className="axis-text" x={padding.left - 8} y={y + 3} textAnchor="end">{`${(step * 100).toFixed(0)}%`}</text>
            </g>
          );
        })}
        {points.map((point, index) => {
          const cx = padding.left + (point.x / maxX) * innerWidth;
          const cy = padding.top + innerHeight - Math.max(0, Math.min(1, point.y)) * innerHeight;
          return (
            <circle
              key={index}
              cx={cx}
              cy={cy}
              r={4}
              fill={point.color}
              fillOpacity={0.75}
              stroke={point.color}
              style={{ cursor: "pointer" }}
              onMouseEnter={(event) => {
                const bounds = event.currentTarget.ownerSVGElement!.getBoundingClientRect();
                setTip({
                  x: (cx / width) * bounds.width,
                  y: (cy / height) * bounds.height,
                  node: (
                    <>
                      <strong>{point.label}</strong>
                      <span>{point.x.toFixed(1)} ms · {(point.y * 100).toFixed(1)}% risk</span>
                    </>
                  )
                });
              }}
              onMouseLeave={() => setTip(undefined)}
            />
          );
        })}
        <text className="axis-text" x={width / 2} y={height - 6} textAnchor="middle">{xLabel}</text>
        <text className="axis-text" x={12} y={padding.top + innerHeight / 2} textAnchor="middle" transform={`rotate(-90 12 ${padding.top + innerHeight / 2})`}>{yLabel}</text>
      </svg>
      {holder}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Confusion matrix
 * ------------------------------------------------------------------ */
export function ConfusionMatrix({ matrix, labels }: { matrix: number[][]; labels: string[] }) {
  const max = Math.max(1, ...matrix.flat());
  return (
    <div className="matrix" style={{ gridTemplateColumns: `minmax(74px, auto) repeat(${labels.length}, minmax(0, 1fr))` }}>
      <div />
      {labels.map((name) => (
        <div key={`head-${name}`} className="matrix-head" title={name}>{name.slice(0, 9)}</div>
      ))}
      {matrix.map((row, rowIndex) => (
        <Row key={labels[rowIndex] ?? rowIndex} name={labels[rowIndex] ?? String(rowIndex)} row={row} rowIndex={rowIndex} max={max} />
      ))}
    </div>
  );
}

function Row({ name, row, rowIndex, max }: { name: string; row: number[]; rowIndex: number; max: number }) {
  return (
    <>
      <div className="matrix-head" style={{ textAlign: "right", paddingRight: 8, alignSelf: "center" }} title={name}>{name.slice(0, 12)}</div>
      {row.map((value, columnIndex) => {
        const intensity = value / max;
        const correct = rowIndex === columnIndex;
        return (
          <div
            key={columnIndex}
            className="matrix-cell"
            title={`${value.toLocaleString()} predictions`}
            style={{
              background: correct
                ? `rgba(43, 213, 118, ${0.1 + intensity * 0.55})`
                : `rgba(255, 92, 92, ${0.08 + Math.min(1, intensity * 6) * 0.5})`,
              color: intensity > 0.4 ? "#fff" : "#a1a1a1"
            }}
          >
            {value === 0 ? "·" : compactNumber(value)}
          </div>
        );
      })}
    </>
  );
}

/* ------------------------------------------------------------------ *
 * Shared bits
 * ------------------------------------------------------------------ */
function Legend({ series }: { series: Series[] }) {
  return (
    <div className="chart-legend">
      {series.map((entry) => (
        <span key={entry.name}>
          <i style={{ background: entry.color }} />
          {entry.name}
        </span>
      ))}
    </div>
  );
}

function Empty({ height, message }: { height: number; message: string }) {
  return (
    <div style={{ height, display: "grid", placeItems: "center" }}>
      <p className="muted" style={{ fontSize: 12 }}>{message}</p>
    </div>
  );
}
