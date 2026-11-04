import { useMemo, useState } from "react";
import type { EventRecord } from "../api";
import { DonutChart, RankedBars } from "../components/Charts";
import { EventTable } from "../components/EventTable";
import { Badge, EmptyState, Icon, Metric, Panel } from "../components/Ui";
import { formatDateTime, label as humanize, percent, relativeTime, shortId, sortedEntries } from "../lib/format";
import type { ViewProps } from "../lib/view";

const VERDICTS = [
  { value: "CONFIRMED_ATTACK", label: "Confirmed attack" },
  { value: "FALSE_POSITIVE", label: "False positive" },
  { value: "WRONG_ATTACK_TYPE", label: "Wrong attack type" },
  { value: "BENIGN", label: "Benign" }
];

const ATTACK_TYPES = ["SQL_INJECTION", "XSS", "COOKIE_INJECTION", "DIRECTORY_TRAVERSAL", "REMOTE_CODE_EXECUTION", "BENIGN"];

export function Review({ snapshot, selected, select, api, mutate, liveIds }: ViewProps) {
  const review = selected ?? snapshot.events[0];
  const feedback = snapshot.feedback;

  const reviewedIds = useMemo(() => new Set(feedback.map((item) => item.eventId)), [feedback]);
  const byVerdict = useMemo(
    () => feedback.reduce<Record<string, number>>((result, item) => {
      result[item.verdict] = (result[item.verdict] ?? 0) + 1;
      return result;
    }, {}),
    [feedback]
  );
  const byOriginal = useMemo(
    () => feedback.reduce<Record<string, number>>((result, item) => {
      const name = item.predictedAttack ?? "UNKNOWN";
      result[name] = (result[name] ?? 0) + 1;
      return result;
    }, {}),
    [feedback]
  );

  const falsePositives = feedback.filter((item) => item.verdict === "FALSE_POSITIVE").length;
  const agreement = feedback.length ? feedback.filter((item) => item.verdict === "CONFIRMED_ATTACK" || (item.verdict === "BENIGN" && item.predictedAttack === "BENIGN")).length / feedback.length : undefined;

  return (
    <div className="stack">
      <div className="grid-4 stagger">
        <Metric label="Reviews submitted" value={feedback.length} detail={`${reviewedIds.size} distinct requests`} tone="info" icon={<Icon name="feedback" size={13} />} />
        <Metric label="Confirmed attacks" value={byVerdict.CONFIRMED_ATTACK ?? 0} detail="Operator agreed with the pipeline" tone="success" icon={<Icon name="check" size={13} />} />
        <Metric label="False positives" value={falsePositives} detail="Flagged for the next curation run" tone="danger" icon={<Icon name="alert" size={13} />} />
        <Metric label="Operator agreement" value={agreement===undefined?"—":percent(agreement, 0)} detail="Confirmed attacks or upheld benign classifications; wrong-type corrections excluded" tone="violet" icon={<Icon name="target" size={13} />} />
      </div>

      <div className="split">
        <Panel title="Choose a request" subtitle="Reviewed requests are marked" flush>
          <EventTable
            events={snapshot.events.slice(0, 50)}
            selected={review}
            onSelect={select}
            highlight={liveIds}
            compact
          />
        </Panel>

        {review ? (
          <FeedbackForm
            event={review}
            alreadyReviewed={reviewedIds.has(review.eventId)}
            submit={(verdict, notes, correctAttackType) =>
              mutate(
                () => api.submitFeedback(review.eventId, verdict, notes, correctAttackType),
                "Review recorded for the next curation run."
              )
            }
          />
        ) : (
          <Panel title="Review">
            <EmptyState title="No requests available" detail="Reviews can be submitted once the gateway journals a request." icon={<Icon name="feedback" />} />
          </Panel>
        )}
      </div>

      <div className="grid-2">
        <Panel title="Verdict distribution">
          <DonutChart data={sortedEntries(byVerdict).map(([name, value]) => ({ label: humanize(name), value }))} centerLabel="reviews" size={140} />
        </Panel>
        <Panel title="Original classification of reviewed requests">
          <RankedBars data={sortedEntries(byOriginal).map(([name, value]) => ({ label: humanize(name), value }))} />
        </Panel>
      </div>

      <Panel title="Submitted reviews" subtitle="Reviewed metadata for curation; model training and policy activation require separate validated runs" flush>
        {feedback.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Submitted</th><th>Request</th><th>Pipeline decision</th><th>Operator verdict</th><th>Note</th><th>Reviewer</th></tr></thead>
              <tbody>
                {feedback.map((item) => (
                  <tr key={item.feedbackId}>
                    <td className="mono">{formatDateTime(item.submittedAt)}<span className="cell-sub">{relativeTime(item.submittedAt)}</span></td>
                    <td>
                      <span className="cell-strong mono">{item.method ?? "?"} {item.path ?? "unknown"}</span>
                      <span className="cell-sub">{shortId(item.eventId, 18)}</span>
                    </td>
                    <td>{humanize(item.predictedAttack ?? "UNKNOWN")}</td>
                    <td>
                      <Badge value={item.verdict} />
                      {item.correctAttackType && <span className="cell-sub">corrected to {humanize(item.correctAttackType)}</span>}
                    </td>
                    <td className="muted">{item.notes || "—"}</td>
                    <td className="muted">{item.submittedBy}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No reviews yet" detail="Submit a verdict above to start building the curated feedback set." icon={<Icon name="feedback" />} />
        )}
      </Panel>
    </div>
  );
}

function FeedbackForm({
  event,
  alreadyReviewed,
  submit
}: {
  event: EventRecord;
  alreadyReviewed: boolean;
  submit: (verdict: string, notes: string, correctAttackType?: string) => Promise<void>;
}) {
  const [verdict, setVerdict] = useState("CONFIRMED_ATTACK");
  const [notes, setNotes] = useState("");
  const [correctAttackType, setCorrectAttackType] = useState("SQL_INJECTION");
  const [saving, setSaving] = useState(false);

  const send = async () => {
    setSaving(true);
    await submit(verdict, notes, verdict === "WRONG_ATTACK_TYPE" ? correctAttackType : undefined);
    setNotes("");
    setSaving(false);
  };

  return (
    <Panel
      title="Record a verdict"
      subtitle={`${event.method ?? "?"} ${event.path ?? "/"}${event.query ? `?${event.query}` : ""}`}
      action={
        <>
          {alreadyReviewed && <Badge value="REVIEWED" tone="neutral" />}
          <Badge value={event.predictedAttack} />
        </>
      }
    >
      <dl className="kv-list" style={{ marginBottom: 14 }}>
        <div><dt>Source</dt><dd className="mono">{event.sourceIp ?? "—"}</dd></div>
        <div><dt>Decision</dt><dd>{humanize(event.action ?? "")} · {percent(event.risk, 2)} risk</dd></div>
        <div><dt>Event</dt><dd className="mono faint">{shortId(event.eventId, 22)}</dd></div>
      </dl>

      <div className="form-grid">
        <label className="field">
          Verdict
          <select value={verdict} onChange={(change) => setVerdict(change.target.value)}>
            {VERDICTS.map((entry) => <option key={entry.value} value={entry.value}>{entry.label}</option>)}
          </select>
        </label>
        {verdict === "WRONG_ATTACK_TYPE" && (
          <label className="field">
            Correct class
            <select value={correctAttackType} onChange={(change) => setCorrectAttackType(change.target.value)}>
              {ATTACK_TYPES.map((entry) => <option key={entry} value={entry}>{humanize(entry)}</option>)}
            </select>
          </label>
        )}
      </div>
      <label className="field" style={{ marginTop: 14 }}>
        Note
        <input value={notes} onChange={(change) => setNotes(change.target.value)} placeholder="Why is this verdict correct?" />
      </label>
      <div className="btn-row" style={{ marginTop: 14 }}>
        <button className="btn primary" onClick={() => void send()} disabled={saving}>
          {saving ? <span className="spinner" /> : <Icon name="check" size={13} />}
          Submit review
        </button>
      </div>
      <p className="muted" style={{ fontSize: 11.5, marginTop: 12 }}>
        Reviews are eligible for metadata curation. Supervised training requires verified request data and a separate validated run; feedback never changes enforcement automatically.
      </p>
    </Panel>
  );
}
