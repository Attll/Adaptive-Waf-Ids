# Adaptive WAF Network Sensor

The sensor classifies replayed CICIDS-compatible flow records locally and writes the latest evidence for each source to Redis under `waf:network:<source-ip>` with a short TTL. The gateway reads this local context with a 25 ms timeout and continues safely without it when Redis or the sensor is unavailable.

Development uses `scripts.replay_network_flows` with prepared CICIDS JSONL. Linux capture uses `scripts.capture_network_flows` and the optional `.[sensor]` dependency, which provides Scapy. No Windows live capture is required for ordinary development.
