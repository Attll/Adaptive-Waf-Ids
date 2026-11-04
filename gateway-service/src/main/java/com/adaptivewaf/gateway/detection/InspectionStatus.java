package com.adaptivewaf.gateway.detection;

/** Coverage of this request, independent of its enforcement action. */
public enum InspectionStatus {
    FULLY_INSPECTED, PARTIALLY_INSPECTED, RULES_ONLY, DETECTION_UNAVAILABLE, INSPECTION_REJECTED
}
