# ANVIL

**ANVIL lints, replays, measures, drafts and decay-monitors Sigma detections.** The rules are treated like code: every one is checked against real attack captures, real clean-host telemetry and a SOC alert budget before it ships, and re-checked when the telemetry underneath it changes.

It is the "factory" half of a detection pipeline: a CTI report becomes a drafted rule, a human reviews it, CI tests it on emulated and benign telemetry, the rule is versioned and deployed, and a monitor watches it decay. All of it runs offline on a laptop.

| Headline (real data) | Result |
| --- | --- |
| SigmaHQ regression captures replayed (463 cases, 497 real events) | **461/461 evaluable detected (100%)** vs 90.7% for the 0.1 engine baseline and 99.1% for pySigma -> SQLite |
| Benign replay: 2,994,137 events (2.55 days, Win10 + Win11 + Server 2022 AD) x 2,803 observable Windows rules | 78 rules fire, **12 blocked** by the 20 alerts/day budget; 27 of 32 medium+ firers are on SigmaHQ's own `known-FPs.csv` |
| OTRF emulations (96 datasets, 752k events) | technique detected in **67/96** (any alert on 93) |
| ATT&CK Enterprise 19.2, Windows (474 techniques + sub-techniques) | **63.1% claimed** by tags, **34.6% validated** on real captures |
| Decay monitor, "pipeline moved to ECS field names" | 425 of 428 broken TP rules flagged statically (99% recall, 100% precision) |



[Detection health dashboard (static demo)](demo/index.html){ .md-button } [GitHub](https://github.com/rakshit-737/anvil){ .md-button }
