package com.adaptivewaf.control.events;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class StreamTicketServiceTest {
    @Test void ticketsAreSingleUse() {
        var service = new StreamTicketService();
        var ticket = service.issue("operator");
        assertTrue(service.isValid(ticket.value()));
        assertFalse(service.isValid(ticket.value()));
        assertFalse(service.isValid("unknown"));
    }
}
