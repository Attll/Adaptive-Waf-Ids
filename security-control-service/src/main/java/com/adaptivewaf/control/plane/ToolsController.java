package com.adaptivewaf.control.plane;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.connection.DataType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

/** Authenticated operator tools; destinations are fixed services, never caller-provided URLs. */
@RestController
@RequestMapping("/v1/control/tools")
public class ToolsController {
    private final StringRedisTemplate redis;
    private final RestClient client;
    private final String gateway, detection, adaptation, token;
    public ToolsController(StringRedisTemplate redis,
        @Value("${DEMO_GATEWAY_URL:http://gateway:8080}") String gateway,
        @Value("${DETECTION_SERVICE_URL:http://detection:8000}") String detection,
        @Value("${ADAPTATION_SERVICE_URL:http://adaptation:8084}") String adaptation,
        @Value("${adaptive-waf.control.internal-token:}") String token) {
        this.redis=redis; this.gateway=gateway; this.detection=detection; this.adaptation=adaptation; this.token=token;
        var factory=new JdkClientHttpRequestFactory(java.net.http.HttpClient.newBuilder().version(java.net.http.HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(2)).followRedirects(java.net.http.HttpClient.Redirect.NEVER).build()); factory.setReadTimeout(Duration.ofSeconds(30));
        client=RestClient.builder().requestFactory(factory).build();
    }
    @GetMapping("/redis")
    public Map<String,Object> cache(@RequestParam(defaultValue="0") String cursor) {
        if (!cursor.matches("[0-9]{1,5}") || Integer.parseInt(cursor)>10000) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid cursor");
        int offset=Integer.parseInt(cursor);var keys=new ArrayList<String>();boolean more;
        try(var scan=redis.scan(org.springframework.data.redis.core.ScanOptions.scanOptions().match("waf:*").count(100).build())) {
            int skipped=0;while(skipped<offset&&scan.hasNext()){scan.next();skipped++;}
            while(keys.size()<50&&scan.hasNext())keys.add(scan.next());
            more=offset+keys.size()<10000&&scan.hasNext();
        }
        var entries=new ArrayList<Map<String,Object>>();
        for (String key:keys) {
            var entry=new LinkedHashMap<String,Object>(); entry.put("key",key);entry.put("ttl",redis.getExpire(key));
            var type=redis.type(key);entry.put("type",type==null?"none":type.code());
            Object value=null;
            if(type==DataType.STRING)value=redis.opsForValue().get(key,0,2047);
            else if(type==DataType.ZSET)value=redis.opsForZSet().rangeWithScores(key,0,24);
            else if(type==DataType.LIST)value=redis.opsForList().range(key,0,24);
            else if(type==DataType.HASH) {var values=new LinkedHashMap<String,String>();try(var items=redis.opsForHash().scan(key,org.springframework.data.redis.core.ScanOptions.scanOptions().count(25).build())) {while(items.hasNext()&&values.size()<25){var item=items.next();values.put(String.valueOf(item.getKey()),String.valueOf(item.getValue()).substring(0,Math.min(2048,String.valueOf(item.getValue()).length())));}}value=values;}
            else if(type==DataType.SET) {var values=new ArrayList<String>();try(var items=redis.opsForSet().scan(key,org.springframework.data.redis.core.ScanOptions.scanOptions().count(25).build())){while(items.hasNext()&&values.size()<25)values.add(items.next());}value=values;}
            entry.put("value",value);entry.put("valueScope","string <=2048 characters; collection sample <=25 elements");entries.add(entry);
        }
        return Map.of("cursor",more?String.valueOf(offset+keys.size()):"0","entries",entries,"scope","Live waf:* keys only; sample-offset pages up to 10000 keys. SCAN order can change; not a transactional snapshot");
    }
    @PostMapping("/models/query")
    public Object models(@RequestBody Map<String,Object> body) {return forward(detection+"/internal/v1/tools/models/query",body);}
    public record Probe(String method,String path,String query,String body,Map<String,String> headers,Map<String,String> cookies) {}
    @PostMapping("/replay")
    public Map<String,Object> replay(@RequestBody Probe probe) throws java.net.URISyntaxException {
        if(probe.path()==null || !probe.path().startsWith("/") || probe.path().length()>2048 || (probe.query()!=null&&probe.query().length()>16000) || (probe.body()!=null&&probe.body().length()>65536))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid bounded request template");
        if(!Set.of("GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS").contains(probe.method()))throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Unsupported method");
        String path=new java.net.URI(null,null,"/backend"+probe.path(),null).toASCIIString().replace("%25","%");
        String query=probe.query()==null?"":java.net.URLEncoder.encode(probe.query(),StandardCharsets.UTF_8).replace("+","%20").replace("%26","&").replace("%3D","=").replace("%25","%");
        String id=UUID.randomUUID().toString();long start=System.nanoTime();
        var request=client.method(org.springframework.http.HttpMethod.valueOf(probe.method())).uri(gateway+path+(query.isEmpty()?"":"?"+query)).header("X-Request-ID",id);
        if(probe.headers()!=null)probe.headers().forEach((key,value)->{if(key.equalsIgnoreCase("Content-Type")||key.equalsIgnoreCase("Cookie"))request.header(key,value);});
        if(probe.cookies()!=null&&!probe.cookies().isEmpty())request.header("Cookie",probe.cookies().entrySet().stream().map(e->e.getKey()+"="+e.getValue()).collect(java.util.stream.Collectors.joining("; ")));
        if(probe.body()!=null&&!probe.body().isEmpty()) {
            if(probe.headers()==null||probe.headers().keySet().stream().noneMatch(key->key.equalsIgnoreCase("Content-Type")))request.header("Content-Type","application/json");
            request.body(probe.body());
        }
        return request.exchange((req,res)->Map.of("status",res.getStatusCode().value(),"requestId",id,"roundTripMs",(System.nanoTime()-start)/1e6,"bodyPreview",new String(res.getBody().readNBytes(4096),StandardCharsets.UTF_8)));
    }
    @PostMapping("/rl/train")
    public Object train(@RequestBody Map<String,Object> body) {return forward(adaptation+"/internal/v1/tools/rl/train",body);}
    @PostMapping("/rl/validate")
    public Object validateRouting() {return forward(adaptation+"/internal/v1/tools/rl/validate",Map.of());}
    @GetMapping("/rl/runs")
    public Object routingRuns() {return fetch(adaptation+"/internal/v1/tools/rl/runs");}
    @GetMapping("/rl/runs/{identifier}")
    public Object routingRun(@PathVariable String identifier) {UUID.fromString(identifier);return fetch(adaptation+"/internal/v1/tools/rl/runs/"+identifier);}
    private Object fetch(String url) {
        try{return client.get().uri(url).header("X-WAF-Internal-Token",token).retrieve().body(Object.class);}
        catch(org.springframework.web.client.RestClientResponseException e){throw new ResponseStatusException(e.getStatusCode(),e.getResponseBodyAsString());}
        catch(org.springframework.web.client.ResourceAccessException e){throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Tool service unavailable");}
    }
    private Object forward(String url,Object body) {
        try {return client.post().uri(url).header("X-WAF-Internal-Token",token).body(body).retrieve().body(Object.class);}
        catch(org.springframework.web.client.RestClientResponseException e){throw new ResponseStatusException(e.getStatusCode(),e.getResponseBodyAsString());}
        catch(org.springframework.web.client.ResourceAccessException e){throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Tool service unavailable");}
    }
}
