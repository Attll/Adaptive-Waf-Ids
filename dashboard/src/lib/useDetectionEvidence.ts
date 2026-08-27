import { useMemo } from "react";
import type { DetectionEvidence, EventRecord } from "../api";
import { asRecord, parseJson } from "./format";

/**
 * Pulls the per-stage inference evidence out of a persisted event. Events recorded while inference was skipped or
 * the detection service was unavailable carry the final decision only, so this returns undefined for those.
 */
export function useDetectionEvidence(event?: EventRecord): DetectionEvidence | undefined {
  return useMemo(() => {
    if (!event) return undefined;
    const detection = asRecord(parseJson(event.detailsJson).detection);
    return detection && detection.risks ? (detection as unknown as DetectionEvidence) : undefined;
  }, [event]);
}
