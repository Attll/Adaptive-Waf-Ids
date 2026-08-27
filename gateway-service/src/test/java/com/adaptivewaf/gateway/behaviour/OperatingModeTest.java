package com.adaptivewaf.gateway.behaviour;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

class OperatingModeTest {
    @Test
    void transitionsThroughConfiguredLoadModes() {
        BehaviourProperties properties = new BehaviourProperties();
        assertEquals(OperatingMode.NORMAL, OperatingMode.forRequestCount(19, properties));
        assertEquals(OperatingMode.ELEVATED, OperatingMode.forRequestCount(20, properties));
        assertEquals(OperatingMode.DEGRADED, OperatingMode.forRequestCount(40, properties));
        assertEquals(OperatingMode.EMERGENCY, OperatingMode.forRequestCount(80, properties));
    }
}
