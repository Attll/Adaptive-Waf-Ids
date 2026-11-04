package com.adaptivewaf.control.events;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/security")
public class SecurityEventController {
    private static final int MAX_LIMIT = 500;
    private static final String ESCALATION_CATEGORY = "security.escalation";
    private final SecurityEventRepository repository;
    private final StreamTicketService tickets;
    private final SecurityEventBroadcaster broadcaster;

    public SecurityEventController(SecurityEventRepository repository, StreamTicketService tickets, SecurityEventBroadcaster broadcaster) {
        this.repository = repository;
        this.tickets = tickets;
        this.broadcaster = broadcaster;
    }

    @GetMapping("/events")
    public Map<String, Object> recent(@RequestParam(defaultValue = "100") int limit,
                                      @RequestParam(required = false) String category,
                                      @RequestParam(required = false) String action,
                                      @RequestParam(required = false) String attack,
                                      @RequestParam(required = false) String sourceIp,
                                      @RequestParam(required = false) Integer sinceMinutes,
                                      @RequestParam(defaultValue = "false") boolean detectionsOnly) {
        List<PersistedSecurityEvent> events = window(Math.max(limit, 200)).stream()
            .filter(event -> category == null || category.equalsIgnoreCase(event.getCategory()))
            .filter(event -> action == null || action.equalsIgnoreCase(event.getAction()))
            .filter(event -> attack == null || attack.equalsIgnoreCase(event.getPredictedAttack()))
            .filter(event -> sourceIp == null || sourceIp.equals(event.getSourceIp()))
            .filter(event -> sinceMinutes == null || event.getOccurredAt().isAfter(Instant.now().minus(sinceMinutes, ChronoUnit.MINUTES)))
            .filter(event -> !detectionsOnly || isDetection(event))
            .limit(bounded(limit))
            .toList();
        return Map.of("events", events, "count", events.size(), "subscribers", broadcaster.subscribers());
    }

    /** Aggregated view of the retained window, used by the overview and live-attack dashboards. */
    @GetMapping("/statistics")
    public Map<String, Object> statistics(@RequestParam(defaultValue = "500") int limit) {
        List<PersistedSecurityEvent> events = window(bounded(limit));
        List<PersistedSecurityEvent> detections = events.stream().filter(SecurityEventController::isDetection).toList();
        List<Double> latencies = events.stream()
            .map(PersistedSecurityEvent::getGatewayLatencyMs)
            .filter(value -> value > 0)
            .sorted()
            .toList();
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("total", events.size());
        summary.put("allTimeTotal",repository.countByCategoryNotAndMethodIsNotNullAndPathIsNotNull(ESCALATION_CATEGORY));
        summary.put("fullyInspected", events.stream().filter(event -> "FULLY_INSPECTED".equals(event.getInspectionStatus())).count());
        summary.put("partiallyInspected", events.stream().filter(event -> "PARTIALLY_INSPECTED".equals(event.getInspectionStatus())).count());
        summary.put("detectionUnavailable", events.stream().filter(event -> "DETECTION_UNAVAILABLE".equals(event.getInspectionStatus())).count());
        summary.put("coverageUnknown", events.stream().filter(event -> event.getInspectionStatus() == null).count());
        summary.put("detections", detections.size());
        summary.put("blocked", events.stream().filter(event -> "BLOCK".equals(event.getAction()) || "TEMPORARY_BLOCK".equals(event.getAction())).count());
        summary.put("rateLimited", events.stream().filter(event -> "RATE_LIMIT".equals(event.getAction())).count());
        summary.put("deepEscalations", events.stream().filter(PersistedSecurityEvent::isDeepModelUsed).count());
        summary.put("uniqueSources", events.stream().map(PersistedSecurityEvent::getSourceIp).filter(java.util.Objects::nonNull).distinct().count());
        summary.put("latencyP50Ms", percentile(latencies, 0.50));
        summary.put("latencyP95Ms", percentile(latencies, 0.95));
        summary.put("latencyP99Ms", percentile(latencies, 0.99));
        summary.put("detectionLatencyMeanMs", mean(events.stream().map(PersistedSecurityEvent::getDetectionLatencyMs).filter(value -> value > 0).toList()));
        summary.put("upstreamLatencyMeanMs", mean(events.stream().map(PersistedSecurityEvent::getUpstreamLatencyMs).filter(value -> value > 0).toList()));
        return Map.of(
            "summary", summary,
            "byAttack", countBy(events, event -> normalize(event.getPredictedAttack())),
            "byAction", countBy(events, event -> normalize(event.getAction())),
            "byMitigation", countBy(events, event -> normalize(event.getMitigation())),
            "byEndpoint", topEntries(countBy(events, event -> event.getMethod() + " " + normalize(event.getPath())), 12),
            "bySource", topEntries(countBy(events, event -> normalize(event.getSourceIp())), 12),
            "byRoute", topEntries(countBy(events, event -> normalize(event.getRoutingPath())), 8),
            "byStatus", countBy(events, event -> String.valueOf(event.getStatusCode())),
            "timeline", timeline(events),
            "sources", sourceProfiles(events));
    }

    /** Issues the short-lived ticket a browser presents when opening the live event stream. */
    @GetMapping("/stream-ticket")
    public Map<String, Object> streamTicket(Authentication authentication) {
        StreamTicketService.Ticket ticket = tickets.issue(authentication.getName());
        return Map.of("ticket", ticket.value(), "expiresAt", ticket.expiresAt().toString(), "path", "/v1/stream/events");
    }

    /** Request-shaped journal entries only: an escalation is a later revision of a request, not a request itself. */
    private List<PersistedSecurityEvent> window(int limit) {
        return repository.findByCategoryNotAndMethodIsNotNullAndPathIsNotNullOrderByOccurredAtDesc(ESCALATION_CATEGORY, PageRequest.of(0, bounded(limit)));
    }

    private static int bounded(int limit) { return Math.max(1, Math.min(limit, MAX_LIMIT)); }

    private static boolean isDetection(PersistedSecurityEvent event) {
        String attack = event.getPredictedAttack();
        return attack != null && java.util.Set.of("SQL_INJECTION", "XSS", "COOKIE_INJECTION", "DIRECTORY_TRAVERSAL",
            "REMOTE_CODE_EXECUTION", "BRUTE_FORCE", "DOS_DDOS", "BOT_ANOMALY").contains(attack);
    }

    private static String normalize(String value) { return value == null || value.isBlank() ? "UNKNOWN" : value; }

    private static Map<String, Long> countBy(List<PersistedSecurityEvent> events, java.util.function.Function<PersistedSecurityEvent, String> key) {
        return events.stream().collect(Collectors.groupingBy(key, LinkedHashMap::new, Collectors.counting()));
    }

    private static Map<String, Long> topEntries(Map<String, Long> counts, int size) {
        return counts.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(size)
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (first, second) -> first, LinkedHashMap::new));
    }

    /** One bucket per minute over the retained window, oldest first, so the console can draw a continuous timeline. */
    private static List<Map<String, Object>> timeline(List<PersistedSecurityEvent> events) {
        if (events.isEmpty()) { return List.of(); }
        Map<Instant, long[]> buckets = new java.util.TreeMap<>();
        Instant newest = events.get(0).getOccurredAt().truncatedTo(ChronoUnit.MINUTES);
        for (int offset = 29; offset >= 0; offset--) {
            buckets.put(newest.minus(offset, ChronoUnit.MINUTES), new long[3]);
        }
        Instant oldest = newest.minus(29, ChronoUnit.MINUTES);
        for (PersistedSecurityEvent event : events) {
            Instant bucket = event.getOccurredAt().truncatedTo(ChronoUnit.MINUTES);
            if (bucket.isBefore(oldest) || bucket.isAfter(newest)) { continue; }
            long[] counts = buckets.get(bucket);
            counts[0]++;
            if (isDetection(event)) { counts[1]++; }
            if ("BLOCK".equals(event.getAction())) { counts[2]++; }
        }
        List<Map<String, Object>> series = new ArrayList<>();
        buckets.forEach((bucket, counts) -> series.add(Map.of(
            "bucket", bucket.toString(), "total", counts[0], "detections", counts[1], "blocked", counts[2])));
        return series;
    }

    /** Per-source-address rollup used for origin mapping. */
    private static List<Map<String, Object>> sourceProfiles(List<PersistedSecurityEvent> events) {
        Map<String, List<PersistedSecurityEvent>> grouped = events.stream()
            .filter(event -> event.getSourceIp() != null)
            .collect(Collectors.groupingBy(PersistedSecurityEvent::getSourceIp, LinkedHashMap::new, Collectors.toList()));
        return grouped.entrySet().stream()
            .map(entry -> {
                List<PersistedSecurityEvent> group = entry.getValue();
                Map<String, Object> profile = new LinkedHashMap<>();
                profile.put("sourceIp", entry.getKey());
                profile.put("requests", group.size());
                profile.put("detections", group.stream().filter(SecurityEventController::isDetection).count());
                profile.put("blocked", group.stream().filter(event -> "BLOCK".equals(event.getAction())).count());
                profile.put("maxRisk", group.stream().mapToDouble(PersistedSecurityEvent::getRisk).max().orElse(0.0));
                profile.put("meanLatencyMs", mean(group.stream().map(PersistedSecurityEvent::getGatewayLatencyMs).filter(value -> value > 0).toList()));
                profile.put("lastSeen", group.stream().map(PersistedSecurityEvent::getOccurredAt).max(Comparator.naturalOrder()).map(Instant::toString).orElse(null));
                profile.put("attacks", topEntries(group.stream().collect(Collectors.groupingBy(
                    event -> normalize(event.getPredictedAttack()), LinkedHashMap::new, Collectors.counting())), 5));
                profile.put("endpoints", topEntries(group.stream().collect(Collectors.groupingBy(
                    event -> normalize(event.getPath()), LinkedHashMap::new, Collectors.counting())), 5));
                return profile;
            })
            .sorted(Comparator.comparingLong(profile -> -((Number) profile.get("requests")).longValue()))
            .limit(25)
            .toList();
    }

    private static double percentile(List<Double> sorted, double quantile) {
        if (sorted.isEmpty()) { return 0.0; }
        int index = (int) Math.ceil(quantile * sorted.size()) - 1;
        return round(sorted.get(Math.max(0, Math.min(index, sorted.size() - 1))));
    }

    private static double mean(List<Double> values) {
        return values.isEmpty() ? 0.0 : round(values.stream().mapToDouble(Double::doubleValue).average().orElse(0.0));
    }

    private static double round(double value) {
        return Double.parseDouble(String.format(Locale.ROOT, "%.3f", value));
    }
}
