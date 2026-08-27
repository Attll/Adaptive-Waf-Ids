package com.adaptivewaf.gateway.detection;

public record DetectionVerdict(double overallRisk, String predictedAttack) { }
