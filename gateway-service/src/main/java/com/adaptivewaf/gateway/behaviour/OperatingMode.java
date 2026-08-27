package com.adaptivewaf.gateway.behaviour;

public enum OperatingMode {
    NORMAL,
    ELEVATED,
    DEGRADED,
    EMERGENCY;

    public boolean permitsModelInference() {
        return this == NORMAL || this == ELEVATED;
    }

    public static OperatingMode forRequestCount(long requestCount, BehaviourProperties properties) {
        if (requestCount >= properties.getEmergencyRequestsPerShortWindow()) { return EMERGENCY; }
        if (requestCount >= properties.getDegradedRequestsPerShortWindow()) { return DEGRADED; }
        if (requestCount >= properties.getElevatedRequestsPerShortWindow()) { return ELEVATED; }
        return NORMAL;
    }
}
