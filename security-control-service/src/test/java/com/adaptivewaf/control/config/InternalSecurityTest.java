package com.adaptivewaf.control.config;

import com.adaptivewaf.control.plane.ControlPlaneService;
import com.adaptivewaf.control.plane.InternalPolicyController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = InternalPolicyController.class,
    properties = "adaptive-waf.control.internal-token=fixture-service-token")
@Import(SecurityConfiguration.class)
class InternalSecurityTest {
    @Autowired MockMvc mvc;
    @MockBean JdbcTemplate jdbc;
    @MockBean ControlPlaneService service;

    @Test void missingOrWrongServiceCredentialIsRejected() throws Exception {
        mvc.perform(get("/internal/v1/gateway-policy")).andExpect(status().isUnauthorized());
        mvc.perform(get("/internal/v1/gateway-policy").header("X-WAF-Internal-Token", "wrong"))
            .andExpect(status().isUnauthorized());
    }

    @Test void validServiceCredentialIsAccepted() throws Exception {
        mvc.perform(get("/internal/v1/gateway-policy").header("X-WAF-Internal-Token", "fixture-service-token"))
            .andExpect(status().isOk());
    }
}
