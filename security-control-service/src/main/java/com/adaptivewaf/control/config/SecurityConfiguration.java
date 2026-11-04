package com.adaptivewaf.control.config;

import javax.sql.DataSource;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {
    @Bean
    @org.springframework.core.annotation.Order(1)
    SecurityFilterChain internalSecurity(HttpSecurity http,
            @org.springframework.beans.factory.annotation.Value("${adaptive-waf.control.internal-token:}") String token) throws Exception {
        var authentication = new org.springframework.web.filter.OncePerRequestFilter() {
            @Override protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request,
                    jakarta.servlet.http.HttpServletResponse response, jakarta.servlet.FilterChain chain)
                    throws java.io.IOException, jakarta.servlet.ServletException {
                String supplied = request.getHeader("X-WAF-Internal-Token");
                if (token.isBlank() || supplied == null || !java.security.MessageDigest.isEqual(
                        token.getBytes(java.nio.charset.StandardCharsets.UTF_8), supplied.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
                    response.sendError(401, "Service credentials are required");
                    return;
                }
                chain.doFilter(request, response);
            }
        };
        return http.securityMatcher("/internal/**").csrf(csrf -> csrf.disable())
            .addFilterBefore(authentication, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll()).build();
    }
    @Bean PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    @Bean ApplicationRunner bootstrapAdministrator(JdbcTemplate jdbc, ControlProperties properties, PasswordEncoder encoder) {
        return arguments -> jdbc.update("insert into admin_users(username, password_hash, role) values (?, ?, 'ADMIN') on conflict (username) do nothing",
            properties.getAdmin().getUsername(), encoder.encode(properties.getAdmin().getInitialPassword()));
    }

    @Bean UserDetailsService users(JdbcTemplate jdbc) {
        return username -> jdbc.query("select username, password_hash, role from admin_users where username = ?", result -> {
            if (!result.next()) { throw new UsernameNotFoundException(username); }
            return User.withUsername(result.getString("username")).password(result.getString("password_hash"))
                .roles(result.getString("role")).build();
        }, username);
    }

    @Bean SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .requestMatchers("/v1/stream/**").permitAll()
                .anyRequest().hasRole("ADMIN"))
            .httpBasic(httpBasic -> httpBasic.authenticationEntryPoint((request, response, exception) ->
                response.sendError(401, "Administrator credentials are required")))
            .build();
    }
}
