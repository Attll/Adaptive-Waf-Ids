package com.adaptivewaf.backend;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class DemoControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @Test
    void helloConfirmsBackendReachability() throws Exception {
        mockMvc.perform(get("/public/hello").header("X-Request-ID", "test-request"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("backend_reached"))
            .andExpect(jsonPath("$.request_id").value("test-request"));
    }

    @Test
    void loginProvidesARepeatableFailedAuthenticationSignal() throws Exception {
        mockMvc.perform(post("/login").header("X-Request-ID", "test-request"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.status").value("invalid_credentials"));
    }
}
