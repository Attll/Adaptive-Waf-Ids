package com.adaptivewaf.gateway.network;

import com.fasterxml.jackson.databind.ObjectMapper;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

class NetworkContextSnapshotTest {
    @Test
    void acceptsOnlyValidatedSensorEvidence() throws Exception {
        NetworkContextSnapshot snapshot = NetworkContextSnapshot.from(new ObjectMapper().readTree("{\"network_risk\":0.92,\"network_class\":\"DOS_DDOS\",\"confidence\":0.88}"));

        assertEquals(0.92, snapshot.risk());
        assertEquals("DOS_DDOS", snapshot.networkClass());
        assertEquals(0.88, snapshot.confidence());
    }

    @Test
    void discardsInvalidRiskEvidence() throws Exception {
        NetworkContextSnapshot snapshot = NetworkContextSnapshot.from(new ObjectMapper().readTree("{\"network_risk\":1.2}"));

        assertEquals(0.0, snapshot.risk());
    }
}
