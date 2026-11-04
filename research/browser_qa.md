# Browser QA — owned local fixture, 28 October 2026

Used the computer-use plugin's documented browser API against disposable fixture identities only. No real credentials, production policy edits, model promotions or training runs were used.

Executed in the first fixture: authenticated Overview, navigation through Escalations, Models, Training, Policy, Access Control, Applications, Network, Review, Services, Audit and Settings; model catalog finished loading. One selected attack-corpus replay was actually blocked, streamed and journalled. It was labeled RCE in the shipped corpus but predicted XSS; this UI observation is not an exact-class research success.

Final healthy fixture `ui-fixture-v3` used the current packaged Java services, real isolated Redis/Rabbit/Postgres, sensor/adaptation, guarded_fixed detection, synchronous deep execution and shadow context. After an earlier fixture's dependencies stopped during a conversation pause, its login failed. It was stopped and replaced; the login message now acknowledges control-service availability rather than asserting only a bad password.

Verified final workflows:

1. Authenticated with fixture-admin and loaded actual DB counts. Request count was 216 for the benchmark requests; synthetic nonrequest rows were excluded, while the infrastructure journal total remained an event count.
2. Research displayed actual model/rule/strategy/context versions, current allocator memory and the V5 measured comparison rows. Missing conformal/verified calibration/reward/reference data was explicitly unavailable. Live promotion stayed disabled.
3. Generator class buttons exposed pressed states. Selected only BENIGN and one request. `/orders/get/ship_via/1` returned 200 and was forwarded, with zero mitigations and zero failed transmissions. UI client round trip was 676.9 ms in this one browser workflow, not a benchmark claim.
4. Actual event stream received the new event; Requests showed the benign record as FULLY_INSPECTED/ALLOW, gateway 644.54 ms and inference 545.23 ms. Filtering by its path produced one matching request after the count animation settled. Selecting the row and Inspect selected opened that record's visualizer with real stages/versions/upstream evidence.
5. Submitted BENIGN feedback with an explicit local-QA note. The DB-backed review table subsequently showed one stored review for event `c3b5292b-1185-4fbb-967…`; the review did not train or promote a model. The Training screen showed the corresponding benign feedback signal and zero registered runs.
6. Services showed all five services healthy and the stream live. Fixed reported-model count excluded rule/strategy/context version entries and displayed six model versions, verified after hot reload.
7. Escalations correctly showed Inline for this synchronous fixture, with no fictitious pending queue.
8. Saved and visually inspected `browser/research-runtime.jpg`. It records one retained fully inspected inference and zero current 60-second RPS after that request aged out, which is expected.

Build/type verification passed. The final v4 fixture additionally verified that the configured external DB URL matches the service connection, and that Research shows actual cumulative process CPU, resident memory, gateway policy v21 and Inline / queue disabled. Its combined measured table includes the separate deep-only control. `browser/research-final.jpg` records those final panels. Full production role/access/reconnection and rich candidate metric chart workflows remain incomplete. No controls that would change live enforcement were exercised.

The fixture is stopped gracefully using its owned STOP file. Browser screenshots and committed reports persist; local ports are ephemeral and are not a deployment URL.
