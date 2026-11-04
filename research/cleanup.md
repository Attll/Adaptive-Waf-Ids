# Cleanup evidence — 28 October 2026

The owned UI fixture v4 completed graceful STOP-file shutdown. Only the named `adaptive-waf-crs-research` and `adaptive-waf-research` Docker Compose projects were stopped. No `down -v`, prune, image/volume deletion or recursive workspace cleanup was run. A CIM query after shutdown found zero project Java JAR processes. Other user containers were not stopped.

All 18 selected baseline artifact hashes match, recorded in `results/artifact_integrity_final.json`. Raw/derived reports and measured source archives remain preserved. User-owned untracked `README.md` and `adaptive-waf-codebase.zip` remain untouched. Expensive training stayed on hold. Development fixture ports are ephemeral; use the reproduction helper to obtain fresh URLs.
