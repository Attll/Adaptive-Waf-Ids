import type { EventRecord } from "../api";
import { formatTime, label as humanize, milliseconds, relativeTime } from "../lib/format";
import { Badge, EmptyState, Icon, MethodTag, RiskBar } from "./Ui";

export function EventTable({
  events,
  selected,
  onSelect,
  compact = false,
  highlight
}: {
  events: EventRecord[];
  selected?: EventRecord;
  onSelect?: (event: EventRecord) => void;
  compact?: boolean;
  highlight?: Set<string>;
}) {
  if (!events.length) {
    return <EmptyState title="No matching requests" detail="Send traffic through the gateway, or relax the current filter." icon={<Icon name="requests" />} />;
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Request</th>
            {!compact && <th>Source</th>}
            <th>Classification</th>
            <th>Risk</th>
            {!compact && <th>Latency</th>}
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr
              key={event.eventId}
              className={[
                onSelect ? "clickable" : "",
                selected?.eventId === event.eventId ? "selected" : "",
                highlight?.has(event.eventId) ? "enter" : ""
              ].filter(Boolean).join(" ")}
              onClick={() => onSelect?.(event)}
            >
              <td>
                <span className="mono">{formatTime(event.occurredAt)}</span>
                {!compact && <span className="cell-sub">{relativeTime(event.occurredAt)}</span>}
              </td>
              <td>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <MethodTag method={event.method} />
                  <span className="path-cell" title={`${event.path ?? "/"}${event.query ? `?${event.query}` : ""}`}>
                    {truncate(`${event.path ?? "/"}${event.query ? `?${event.query}` : ""}`, compact ? 26 : 44)}
                  </span>
                </div>
                {!compact && <span className="cell-sub">HTTP {event.statusCode} · {humanize(event.mitigation ?? "—")}</span>}
              </td>
              {!compact && <td className="mono muted">{event.sourceIp ?? "—"}</td>}
              <td>
                <span className="cell-strong">{humanize(event.predictedAttack ?? "UNKNOWN")}</span>
                {!compact && event.deepModelUsed && <span className="cell-sub">deep escalation</span>}
              </td>
              <td><RiskBar risk={event.risk} /></td>
              {!compact && <td className="mono muted">{milliseconds(event.gatewayLatencyMs, 1)}</td>}
              <td><Badge value={event.action} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function truncate(value: string, size: number) {
  return value.length > size ? `${value.slice(0, size - 1)}…` : value;
}
