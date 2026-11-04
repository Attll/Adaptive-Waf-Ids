# Versioned network feature validation

The old live-capture extractor is **not certified equivalent** to the CICIDS training feature generator. Matching 38 column names/order does not validate units or statistics. The source audit identifies concrete differences:

| Quantity | Legacy `frame-population-v1` | Opt-in `payload-sample-v2` | Independent source basis |
|---|---|---|---|
| Length totals/statistics/rates | Whole captured frame bytes | Declared TCP/UDP payload bytes | CICFlowMeter `PacketReader` uses transport payload length; `BasicFlow` accumulates payload bytes |
| Standard deviation | Population denominator n | Sample denominator n−1, zero for <=1 observation | CICFlowMeter uses Apache Commons Math SummaryStatistics, whose default variance is sample variance |
| Flow windows and termination | Bounded local windows | Same bounded local windows | Not established equivalent to native CICFlowMeter full-flow segmentation |
| Activity threshold / zero-duration handling / windows / IPv6 details | Local definitions | Local definitions remain | Need a pinned native reference campaign; two corrected quantities do not establish full equivalence |

Primary code/docs inspected on 28 October 2026: [CICFlowMeter PacketReader](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java), [BasicFlow](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java), [Apache SummaryStatistics](https://commons.apache.org/proper/commons-math/javadocs/api-3.6.1/org/apache/commons/math3/stat/descriptive/SummaryStatistics.html). These mutable upstream sources motivate fixes; they are not a pinned executable native reference for this dataset. IPv4 and IPv6 timestamp branches and initialization/window behavior also warrant reference testing. No downloaded reference PCAP or authoritative matching CSV is available.

Legacy capture remains the default. The v2 contract requires measured payload lengths and rejects fragments/truncation rather than guessing reassembly. Offline Scapy tests use generated Ethernet PCAPs with fixed MAC addresses (no neighbor discovery), IPv6 UDP, Ethernet padding, and explicit malformed packets. A two-packet arithmetic fixture independently specifies all 38 expected features and checks both that v2 matches and that v1 differs. This fixture is **CONTROLLED_ARITHMETIC**, not native CICFlowMeter output. The first tests exposed the missing optional Scapy dependency and unspecified synthetic MAC addresses; installing declared `scapy==2.8.0` and making fixture addresses explicit resolved those setup failures. No driver or capture service was installed.

The comparison tool requires an exact PCAP hash and reference provenance. Reference JSON contains `pcap_sha256`, `reference_kind` (`CONTROLLED_ARITHMETIC` or `CICFLOWMETER_REFERENCE`), `reference_provenance`, optional `window_bounds`, and `flows`. Each flow contains `key` = `[source_ip,destination_ip,source_port,destination_port,protocol]`, a zero-based `window`, and the full 38-name `features` mapping. Missing windows/features fail; tolerance defaults to absolute/relative 1e−6. Inputs are bounded to 64 MiB PCAP, 10 MiB reference, 10,000 packets. A caller-provided provenance label is not proof of independence; review the tool revision/native commands and reference-generation history separately.

```powershell
.\.venv\Scripts\python.exe -m pip install "scapy==2.8.0"
.\.venv\Scripts\python.exe -m unittest tests.test_network_feature_contract -v
# Prepared command: these independently generated inputs are still unavailable.
.\.venv\Scripts\python.exe -m scripts.compare_network_features --pcap research/private-inputs/reference.pcap --reference research/private-inputs/cicflowmeter-reference.json --contract payload-sample-v2 --output research/runs/network-reference-001.json
```

Do not switch deployed network context merely because this regression fixture passes. The request's live security-change approval requirement remains applicable. A reviewed migration must establish matched extractor revision, payload/timestamp conventions, flow boundaries, directions, flags, missing values, model compatibility and per-class effects before choosing v2. Captured sensor evidence now preserves the declared feature contract alongside observation scope; old API callers retain `PROVIDED_FLOW` semantics. Existing model artifacts and deployment selection are unchanged.
