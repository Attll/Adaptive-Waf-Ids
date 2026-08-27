import { useMemo, useState } from "react";
import type { Audit } from "../api";
import { DonutChart, RankedBars } from "../components/Charts";
import { Badge, EmptyState, Icon, Metric, Panel, Segmented } from "../components/Ui";
import { formatDateTime, label as humanize, parseJson, relativeTime, scalar, shortId, sortedEntries } from "../lib/format";
import type { ViewProps } from "../lib/view";

type Mode = "table" | "timeline";

export function AuditPage({ snapshot }: ViewProps) {
  const [mode, setMode] = useState<Mode>("table");
  const [filter, setFilter] = useState("");

  const entries = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return snapshot.audit;
    return snapshot.audit.filter((item) =>
      [item.administrator, item.action, item.entityType, item.entityId, item.newValueJson].join(" ").toLowerCase().includes(needle)
    );
  }, [snapshot.audit, filter]);

  const byActor = useMemo(() => tally(entries, (item) => item.administrator), [entries]);
  const byAction = useMemo(() => tally(entries, (item) => item.action), [entries]);
  const byEntity = useMemo(() => tally(entries, (item) => item.entityType), [entries]);

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Recorded changes" value={snapshot.audit.length} detail={`${Object.keys(byActor).length} distinct actors`} tone="info" icon={<Icon name="audit" size={13} />} />
        <Metric label="Operator actions" value={entries.filter((item) => item.administrator !== "training-adaptation-service").length} detail="Made from this console" tone="violet" icon={<Icon name="settings" size={13} />} />
        <Metric label="Automated actions" value={entries.filter((item) => item.administrator === "training-adaptation-service").length} detail="Written by the adaptation workflow" tone="warning" icon={<Icon name="training" size={13} />} />
        <Metric label="Most recent" value={snapshot.audit[0] ? relativeTime(snapshot.audit[0].occurredAt) : "—"} detail={snapshot.audit[0] ? humanize(snapshot.audit[0].action) : "No changes yet"} tone="success" icon={<Icon name="clock" size={13} />} />
      </div>

      <div className="toolbar">
        <div className="search-bar">
          <Icon name="search" size={14} />
          <input placeholder="Filter by actor, action, entity, or changed value" value={filter} onChange={(event) => setFilter(event.target.value)} />
        </div>
        <Segmented<Mode>
          value={mode}
          onChange={setMode}
          options={[{ value: "table", label: "Table" }, { value: "timeline", label: "Timeline" }]}
        />
        <span className="toolbar-count">{entries.length} entries</span>
      </div>

      <div className="grid-3">
        <Panel title="By operation"><DonutChart data={sortedEntries(byAction).map(([name, value]) => ({ label: humanize(name), value }))} centerLabel="changes" size={132} /></Panel>
        <Panel title="By actor"><RankedBars data={sortedEntries(byActor).map(([name, value]) => ({ label: name, value }))} /></Panel>
        <Panel title="By entity"><RankedBars data={sortedEntries(byEntity).map(([name, value]) => ({ label: humanize(name), value }))} /></Panel>
      </div>

      <Panel title="Administrator activity" subtitle="Newest first; every governed change is recorded" flush={mode === "table"}>
        {!entries.length ? (
          <EmptyState title="No changes recorded" detail="Policy edits, blocks, and lifecycle transitions all appear here." icon={<Icon name="audit" />} />
        ) : mode === "table" ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>When</th><th>Actor</th><th>Operation</th><th>Target</th><th>Change</th></tr></thead>
              <tbody>
                {entries.map((item) => (
                  <tr key={item.auditId}>
                    <td className="mono">{formatDateTime(item.occurredAt)}<span className="cell-sub">{relativeTime(item.occurredAt)}</span></td>
                    <td className="cell-strong">{item.administrator}</td>
                    <td><Badge value={item.action} /></td>
                    <td>{humanize(item.entityType)}<span className="cell-sub mono">{shortId(item.entityId, 20)}</span></td>
                    <td><ChangeSummary item={item} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="timeline-rail">
            {entries.map((item) => (
              <div className="timeline-item" key={item.auditId} style={{ ["--tone" as string]: toneFor(item.action) }}>
                <div className="when">{formatDateTime(item.occurredAt)} · {relativeTime(item.occurredAt)}</div>
                <div className="what">
                  <strong>{item.administrator}</strong> performed <strong>{humanize(item.action)}</strong> on {humanize(item.entityType)}{" "}
                  <span className="mono faint">{shortId(item.entityId, 16)}</span>
                </div>
                <div style={{ marginTop: 6 }}><ChangeSummary item={item} /></div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}

function ChangeSummary({ item }: { item: Audit }) {
  const next = parseJson(item.newValueJson);
  const previous = parseJson(item.oldValueJson);
  const preferred = ["modelName", "artifactVersion", "status", "version", "blockRiskThreshold", "rateLimitShortWindow", "sourceIp", "reason", "shadowMode", "enabled", "name", "upstreamUrl", "verdict"];
  const entries = preferred.filter((key) => next[key] !== undefined).map((key) => [key, next[key]] as const);

  if (!entries.length) {
    const changed = Object.keys(next).filter(
      (key) => scalar(next[key]) !== scalar(previous[key]) && !["metricsJson", "driftJson", "comparison", "metrics"].includes(key)
    );
    entries.push(...changed.slice(0, 3).map((key) => [key, next[key]] as const));
  }
  if (!entries.length) return <span className="muted">Lifecycle metadata recorded</span>;

  return (
    <div className="chip-row">
      {entries.slice(0, 3).map(([key, value]) => {
        const before = previous[key];
        const changed = before !== undefined && scalar(before) !== scalar(value);
        return (
          <span className="chip" key={key}>
            {humanize(key)}{" "}
            {changed && <span className="faint" style={{ textDecoration: "line-through" }}>{scalar(before)}</span>}
            <strong>{scalar(value)}</strong>
          </span>
        );
      })}
    </div>
  );
}

function toneFor(action: string): string {
  if (["BLOCK", "RETIRE", "DISABLE"].includes(action)) return "#ff5c5c";
  if (["PROMOTE", "APPROVE", "ENABLE", "CREATE"].includes(action)) return "#2bd576";
  if (["UPDATE", "ASSIGN"].includes(action)) return "#3b82f6";
  return "#6e6e6e";
}

function tally<T>(items: T[], key: (item: T) => string): Record<string, number> {
  return items.reduce<Record<string, number>>((result, item) => {
    const name = key(item);
    result[name] = (result[name] ?? 0) + 1;
    return result;
  }, {});
}
