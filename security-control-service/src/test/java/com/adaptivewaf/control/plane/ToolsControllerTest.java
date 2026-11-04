package com.adaptivewaf.control.plane;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.server.ResponseStatusException;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.Map;

class ToolsControllerTest {
    private final ToolsController tools=new ToolsController(mock(StringRedisTemplate.class),"http://127.0.0.1:1","http://127.0.0.1:1","http://127.0.0.1:1","fixture");
    @Test void rejectsInvalidScanAndRequestBeforeNetworkAccess() {
        assertThrows(ResponseStatusException.class,()->tools.cache("0;KEYS *"));
        assertThrows(ResponseStatusException.class,()->tools.replay(new ToolsController.Probe("GET","http://external.test/",null,null,null,null)));
        assertThrows(ResponseStatusException.class,()->tools.replay(new ToolsController.Probe("TRACE","/",null,null,Map.of(),Map.of())));
    }
    @Test void forwardsJsonWithServiceCredentialOverActualHttp() throws Exception {
        var server=com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1",0),0);
        var received=new java.util.concurrent.atomic.AtomicReference<String>();
        var credential=new java.util.concurrent.atomic.AtomicReference<String>();
        server.createContext("/internal/v1/tools/models/query",exchange->{
            received.set(new String(exchange.getRequestBody().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));
            credential.set(exchange.getRequestHeaders().getFirst("X-WAF-Internal-Token"));
            byte[] response="{\"model_only\":true}".getBytes();exchange.getResponseHeaders().set("Content-Type","application/json");exchange.sendResponseHeaders(200,response.length);exchange.getResponseBody().write(response);exchange.close();
        });
        server.start();
        try {
            var client=new ToolsController(mock(StringRedisTemplate.class),"http://127.0.0.1:1","http://127.0.0.1:"+server.getAddress().getPort(),"http://127.0.0.1:1","fixture-token");
            var result=(Map<?,?>)client.models(Map.of("stage","triage"));
            assertEquals(Boolean.TRUE,result.get("model_only"));
            assertTrue(received.get().contains("triage"));assertEquals("fixture-token",credential.get());
        } finally {server.stop(0);}
    }
    @Test void readsRealRedisValuesAndTtlWhenFixtureEnabled() {
        String port=System.getenv("WAF_TEST_REDIS_PORT");org.junit.jupiter.api.Assumptions.assumeTrue(port!=null);
        var connection=new org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory("127.0.0.1",Integer.parseInt(port));connection.afterPropertiesSet();
        var redis=new StringRedisTemplate(connection);String key="waf:tools-test:"+java.util.UUID.randomUUID();
        try {
            redis.opsForValue().set(key,"fixture-value",java.time.Duration.ofSeconds(30));
            var client=new ToolsController(redis,"http://127.0.0.1:1","http://127.0.0.1:1","http://127.0.0.1:1","fixture");
            var result=client.cache("0");var entries=(java.util.List<Map<String,Object>>)result.get("entries");
            var entry=entries.stream().filter(row->key.equals(row.get("key"))).findFirst().orElseThrow();
            assertEquals("fixture-value",entry.get("value"));assertEquals("string",entry.get("type"));assertTrue(((Long)entry.get("ttl"))>0);
        } finally {redis.delete(key);connection.destroy();}
    }
}
