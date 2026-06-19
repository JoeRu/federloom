# Graph Report - /root/swarmguard  (2026-06-19)

## Corpus Check
- 83 files · ~133,533 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1005 nodes · 1905 edges · 60 communities (51 shown, 9 thin omitted)
- Extraction: 81% EXTRACTED · 19% INFERRED · 0% AMBIGUOUS · INFERRED: 369 edges (avg confidence: 0.82)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `42e43db`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Person Identity & Trust Crypto|Person Identity & Trust Crypto]]
- [[_COMMUNITY_Config & Defaults|Config & Defaults]]
- [[_COMMUNITY_BadgerDB Reputation Engine|BadgerDB Reputation Engine]]
- [[_COMMUNITY_swarmctl CLI Commands|swarmctl CLI Commands]]
- [[_COMMUNITY_SQLite Observability Output|SQLite Observability Output]]
- [[_COMMUNITY_CrowdSec Ingest Adapter|CrowdSec Ingest Adapter]]
- [[_COMMUNITY_Node Orchestration & Enforce Sinks|Node Orchestration & Enforce Sinks]]
- [[_COMMUNITY_Prometheus Observability Output|Prometheus Observability Output]]
- [[_COMMUNITY_API Blocklist & CTI Handlers|API Blocklist & CTI Handlers]]
- [[_COMMUNITY_YAML Rules Engine|YAML Rules Engine]]
- [[_COMMUNITY_libp2p DHT & Transport|libp2p DHT & Transport]]
- [[_COMMUNITY_API Server Integration Tests|API Server Integration Tests]]
- [[_COMMUNITY_Federation Invitation Bundle|Federation Invitation Bundle]]
- [[_COMMUNITY_Mailcow Log Ingest|Mailcow Log Ingest]]
- [[_COMMUNITY_Grafana & Monitoring Plans|Grafana & Monitoring Plans]]
- [[_COMMUNITY_SSE Events Handler Tests|SSE Events Handler Tests]]
- [[_COMMUNITY_Rule & RuleSet Evaluation|Rule & RuleSet Evaluation]]
- [[_COMMUNITY_Federation UX Docs & Setup|Federation UX Docs & Setup]]
- [[_COMMUNITY_CrowdSec Enforce Sink|CrowdSec Enforce Sink]]
- [[_COMMUNITY_BurstStore Sliding Window|BurstStore Sliding Window]]
- [[_COMMUNITY_Deploy Node Configs|Deploy Node Configs]]
- [[_COMMUNITY_API Blocklist Handler Tests|API Blocklist Handler Tests]]
- [[_COMMUNITY_Social Trust Anchors Design|Social Trust Anchors Design]]
- [[_COMMUNITY_Spamtrap File-Tail Ingest|Spamtrap File-Tail Ingest]]
- [[_COMMUNITY_Production Rules (YAML)|Production Rules (YAML)]]
- [[_COMMUNITY_Anchor & Cert Store|Anchor & Cert Store]]
- [[_COMMUNITY_YAML Rules Engine Design|YAML Rules Engine Design]]
- [[_COMMUNITY_Node Key (libp2p Identity)|Node Key (libp2p Identity)]]
- [[_COMMUNITY_API Score Handler Tests|API Score Handler Tests]]
- [[_COMMUNITY_Go Client Library|Go Client Library]]
- [[_COMMUNITY_DNSBL DNS Server|DNSBL DNS Server]]
- [[_COMMUNITY_SwarmGuard Core Docs|SwarmGuard Core Docs]]
- [[_COMMUNITY_libp2p Cluster Tests|libp2p Cluster Tests]]
- [[_COMMUNITY_API Server Unit Tests|API Server Unit Tests]]
- [[_COMMUNITY_Honeypot Deploy (Cowrie + OpenCanary)|Honeypot Deploy (Cowrie + OpenCanary)]]
- [[_COMMUNITY_CrowdSec Sink Tests|CrowdSec Sink Tests]]
- [[_COMMUNITY_Changelog & Architecture|Changelog & Architecture]]
- [[_COMMUNITY_Reputation Store Engine|Reputation Store Engine]]
- [[_COMMUNITY_BadgerDB Store Tests|BadgerDB Store Tests]]
- [[_COMMUNITY_Gossip Protocol Tests|Gossip Protocol Tests]]
- [[_COMMUNITY_Client Library Tests|Client Library Tests]]
- [[_COMMUNITY_Corroboration Score Tests|Corroboration Score Tests]]
- [[_COMMUNITY_Wire Protocol Messages|Wire Protocol Messages]]
- [[_COMMUNITY_DNSBL Design & Plan|DNSBL Design & Plan]]
- [[_COMMUNITY_Wire Protocol Tests|Wire Protocol Tests]]
- [[_COMMUNITY_Mailcow Sensor Plan|Mailcow Sensor Plan]]
- [[_COMMUNITY_Effectiveness Report Script|Effectiveness Report Script]]
- [[_COMMUNITY_SSE Events Handler|SSE Events Handler]]
- [[_COMMUNITY_API Score Handler|API Score Handler]]
- [[_COMMUNITY_Mailcow Bootstrap Script|Mailcow Bootstrap Script]]
- [[_COMMUNITY_Metrics Exporter Script|Metrics Exporter Script]]
- [[_COMMUNITY_Federation Package Tests|Federation Package Tests]]
- [[_COMMUNITY_Setup Package Tests|Setup Package Tests]]
- [[_COMMUNITY_Status Package Tests|Status Package Tests]]
- [[_COMMUNITY_WordPress Bootstrap Script|WordPress Bootstrap Script]]
- [[_COMMUNITY_Trust Wire Types|Trust Wire Types]]
- [[_COMMUNITY_CTI Import Script|CTI Import Script]]

## God Nodes (most connected - your core abstractions)
1. `GeneratePersonKey()` - 35 edges
2. `Config` - 32 edges
3. `IssueCert()` - 32 edges
4. `PersonPub()` - 30 edges
5. `EncodePub()` - 27 edges
6. `Node` - 24 edges
7. `SaveAnchors()` - 22 edges
8. `CrowdSec` - 21 edges
9. `Open()` - 19 edges
10. `eval()` - 18 edges

## Surprising Connections (you probably didn't know these)
- `SSH Brute Burst Rule (15 events / 10 min)` --conceptually_related_to--> `BurstStore — in-memory sliding-window burst counter`  [INFERRED]
  deploy/mailcow/rules.yaml → docs/superpowers/plans/2026-06-14-rules-engine.md
- `Wire SchemaVersion 0→1 Bump (additive PeerCert)` --conceptually_related_to--> `PeerCert — wire vouching certificate (Ed25519)`  [INFERRED]
  CHANGELOG.md → docs/superpowers/specs/2026-06-12-social-trust-anchors-design.md
- `Scaling by Querying Not Replicating` --conceptually_related_to--> `ipset Enforcement Backend (O(1))`  [INFERRED]
  README.md → deploy/examples/config.solo.yaml
- `addConfigFlag()` --calls--> `Defaults()`  [INFERRED]
  cmd/swarmctl/common.go → internal/config/config.go
- `cmdIdentity()` --calls--> `LoadOrCreateNodeKey()`  [INFERRED]
  cmd/swarmctl/identity.go → internal/identity/nodekey.go

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Federation Node Deployment Pattern (config + rules + docker-compose)** — honeypot_config, honeypot_docker_compose, honeypot_config_sensor_role, concept_bootstrap_relay_peer [INFERRED 0.85]
- **Three Live Federated Nodes (honeypot, mailcow, wordpress) sharing relay peer** — honeypot_config, mailcow_config, wordpress_config, concept_bootstrap_relay_peer [EXTRACTED 0.95]
- **Observability Stack (Prometheus + SQLite + Grafana)** — swarmguard_changelog_observability, swarmguard_changelog_prometheus_metrics, swarmguard_changelog_sqlite_tables, datasources_swarmguard_sqlite, dashboards_swarmguard [INFERRED 0.85]
- **Dual-Output Observability Pipeline (Observer + Prometheus + SQLite)** — plans_2026_06_14_observer_struct, plans_2026_06_14_prometheus_output, plans_2026_06_14_sqlite_output [EXTRACTED 1.00]
- **Federation UX Command Trio (setup + invite/join + status)** — plans_2026_06_18_cmd_setup, plans_2026_06_18_cmd_federation, plans_2026_06_18_cmd_status [EXTRACTED 1.00]
- **Effectiveness Monitoring Triangle (Go metrics + textfile exporter + CLI report)** — plans_2026_06_16_effectiveness_metrics, plans_2026_06_16_textfile_exporter, plans_2026_06_16_effectiveness_report [EXTRACTED 1.00]

## Communities (60 total, 9 thin omitted)

### Community 0 - "Person Identity & Trust Crypto"
Cohesion: 0.08
Nodes (73): newTestNode(), TestAnchoredPersonCountsOnce(), TestExpiredVouchIsStranger(), TestPersonRemovalAppliesImmediately(), TestSybilStrangerFloodCapped(), TestVouchForgedSignatureIsStranger(), TestVouchReplayIsStranger(), T (+65 more)

### Community 1 - "Config & Defaults"
Cohesion: 0.06
Nodes (49): APIConfig, Config, Defaults(), Load(), LoadYAML(), TestBootstrapPeersDefaultEmpty(), TestBootstrapPeersFromYAML(), TestDefaultsAreValid() (+41 more)

### Community 2 - "BadgerDB Reputation Engine"
Cohesion: 0.07
Nodes (34): mockSink, TestNeverBlockPoisoningLoopback(), TestNeverBlockPoisoningRFC1918(), TestNeverBlockPublicIPNotProtected(), TestSybilFloodHighTrustCapped(), TestSybilFloodScoreCapped(), mockSink, TestPipelineBlockAfterThreshold() (+26 more)

### Community 3 - "swarmctl CLI Commands"
Cohesion: 0.10
Nodes (37): Config, PeerCert, PublicKey, Anchor, Config, PeerCert, Time, FlagSet (+29 more)

### Community 4 - "SQLite Observability Output"
Cohesion: 0.07
Nodes (28): DB, Context, Event, Mutex, ObservabilityConfig, prometheusOutput, ReputationConfig, sqliteOutput (+20 more)

### Community 5 - "CrowdSec Ingest Adapter"
Cohesion: 0.10
Nodes (32): Client, CrowdSec, CrowdSec, mapScenario(), NewCrowdSec(), crowdSecForTest(), crowdSecMachineForTest(), TestCrowdSec_FetchAlerts_ScenarioMapping() (+24 more)

### Community 6 - "Node Orchestration & Enforce Sinks"
Cohesion: 0.07
Nodes (26): NewIpset(), IpsetSink, Context, BadgerStore, BurstStore, Config, Context, Duration (+18 more)

### Community 7 - "Prometheus Observability Output"
Cohesion: 0.10
Nodes (30): CounterVec, Gauge, GaugeVec, HistogramVec, Observer, T, Context, Event (+22 more)

### Community 8 - "API Blocklist & CTI Handlers"
Cohesion: 0.09
Nodes (24): blockEntry, blocklistFilter, EventMsg, New(), StoreReader, MatchesPatterns(), PurposePatterns(), ResolveTaxonomy() (+16 more)

### Community 9 - "YAML Rules Engine"
Cohesion: 0.25
Nodes (31): Action, BurstStore, Event, RuleSet, ScoreRecord, T, emptyBurst(), ev() (+23 more)

### Community 10 - "libp2p DHT & Transport"
Cohesion: 0.10
Nodes (20): AddrInfo, CancelFunc, ID, Context, Host, IpfsDHT, NodeMode, Node (+12 more)

### Community 11 - "API Server Integration Tests"
Cohesion: 0.15
Nodes (17): Addr, responseRecorder, newTestServer(), query(), TestListedIPReturnsA127(), TestListedIPTypeAIncludesTXT(), TestListedIPTypeTXT(), TestMinScoreFallsBackToBlockThreshold() (+9 more)

### Community 12 - "Federation Invitation Bundle"
Cohesion: 0.17
Nodes (23): Bundle, FedInfo, NewInvitation(), ReadInvitation(), makeTestConfig(), setupKeys(), TestInvitationBootstrapPeerContainsPeerID(), TestInvitationRoundTrip() (+15 more)

### Community 13 - "Mailcow Log Ingest"
Cohesion: 0.19
Nodes (16): logFetcher, dockerFetch(), NewMailcow(), NewMailcowWithFetcher(), makeMailcow(), TestMailcowDovecotIMAPAuthFailed(), TestMailcowDovecotPOP3AuthFailed(), TestMailcowPostfixSASLLoginFailure() (+8 more)

### Community 14 - "Grafana & Monitoring Plans"
Cohesion: 0.14
Nodes (21): Expected Unblock Due-Time Computation, Grafana Dashboard JSON (swarmguard-dashboard.json), Grafana Observability Implementation Plan, ObservabilityConfig, Observer Fan-out Struct, Prometheus Output (prometheusOutput), rules.Evaluate Returns Rule Name, SQLite Output (sqliteOutput) (+13 more)

### Community 15 - "SSE Events Handler Tests"
Cohesion: 0.16
Nodes (14): flushRecorder, newFlushRecorder(), newNoFlushWriter(), newTestServer(), TestHandleEvents_Connect(), TestHandleEvents_Disconnect(), TestHandleEvents_NoFlusher(), noFlushWriter (+6 more)

### Community 16 - "Rule & RuleSet Evaluation"
Cohesion: 0.15
Nodes (16): BurstStore, Event, Mutex, Node, RWMutex, ScoreRecord, Time, Action (+8 more)

### Community 17 - "Federation UX Docs & Setup"
Cohesion: 0.13
Nodes (19): Person-to-Person Trust Pairing, Getting Started Guide, Join Existing Federation (Option C), Key Management Reference, Solo Node Setup (Option A), Start New Federation (Option B), Bootstrap Peer Config Implementation Plan, BootstrapPeers Config Field (+11 more)

### Community 18 - "CrowdSec Enforce Sink"
Cohesion: 0.18
Nodes (11): NewCrowdSec(), CrowdSecSink, csEnforcedAuthReq, csEnforcedAuthResp, Client, Context, Duration, EnforceConfig (+3 more)

### Community 19 - "BurstStore Sliding Window"
Cohesion: 0.20
Nodes (13): burstKey, Duration, Mutex, Time, T, NewBurstStore(), TestBurstCount_DifferentReasonIsolated(), TestBurstCount_Empty() (+5 more)

### Community 20 - "Deploy Node Configs"
Cohesion: 0.22
Nodes (15): Bootstrap Relay Peer (12D3KooWBvpzbEB...), Reputation Decay Half-Life (168h default), ipset Enforcement Backend (O(1)), Solo Config Example, Mailcow Node Config, DNSBL Interface (port 5353), Mailcow Logs Ingest (postfix + dovecot containers), Spamtrap Ingest (+7 more)

### Community 21 - "API Blocklist Handler Tests"
Cohesion: 0.25
Nodes (11): containsReason(), countNonEmptyLines(), newListServer(), TestHandleBlocklist_All(), TestHandleBlocklist_Purpose(), TestHandleBlocklist_ReasonFilter(), TestHandleCrowdSecCTI_PlainText(), listStoreStub (+3 more)

### Community 22 - "Social Trust Anchors Design"
Cohesion: 0.24
Nodes (14): Corroboration Group — Person-level diversity vote counting, Federation Modes — solo / federated / isolated, Key Management Policy — issuance, rotation, revocation, PeerCert — wire vouching certificate (Ed25519), Person-to-Person Trust Pairing via Identity Bundles, Social Trust Anchors — Ed25519 Person Identity + Vouching, Stranger Score Cap — Sybil flood mitigation, Federation Guide (+6 more)

### Community 23 - "Spamtrap File-Tail Ingest"
Cohesion: 0.25
Nodes (9): NewSpamtrap(), TestSpamtrapEmitsEvent(), TestSpamtrapMultipleIPs(), TestSpamtrapSkipsComments(), TestSpamtrapSkipsInvalidIP(), Context, Event, SpamtrapConfig (+1 more)

### Community 24 - "Production Rules (YAML)"
Cohesion: 0.19
Nodes (14): Mailcow Docker Compose (sidecar), Host Network Mode for Mailcow Sidecar, Mailcow Rules (production node), CrowdSec SMTP Ban Rule, Score-Based Fallback Rule, Spamtrap Hit Rule, SSH Brute Burst Rule (15 events / 10 min), Pure YAML Rules Engine (+6 more)

### Community 25 - "Anchor & Cert Store"
Cohesion: 0.26
Nodes (9): fileStat, Anchor, Duration, PeerCert, RWMutex, Time, fileStat, Store (+1 more)

### Community 26 - "YAML Rules Engine Design"
Cohesion: 0.24
Nodes (12): Client Config (smoke-test federated peer), Client Docker Compose, Client Rules (smoke-test), BurstStore — in-memory sliding-window burst counter, CrowdSec LAPI Ingest Adapter, File Hot-Reload Pattern (mtime+size fileStat), YAML Rules Engine — hot-reloadable first-match rules, Example Rules (deploy/examples/rules.yaml) (+4 more)

### Community 27 - "Node Key (libp2p Identity)"
Cohesion: 0.27
Nodes (9): checkKeyPerms(), LoadOrCreateNodeKey(), TestNodeKeyFileMode(), TestNodeKeyRejectsCorruptFile(), TestNodeKeyRejectsLooseperms(), TestNodeKeyStableAcrossLoads(), T, PrivKey (+1 more)

### Community 28 - "API Score Handler Tests"
Cohesion: 0.29
Nodes (8): newScoreServer(), TestHandleScore_Found(), TestHandleScore_MissingIP(), TestHandleScore_NotFound(), scoreStoreStub, ScoreRecord, Server, T

### Community 29 - "Go Client Library"
Cohesion: 0.31
Nodes (6): BlockEntry, BlocklistOpts, EventMsg, ScoreResponse, Context, Time

### Community 30 - "DNSBL DNS Server"
Cohesion: 0.24
Nodes (8): New(), StoreReader, DNSBLConfig, Context, Msg, ReputationConfig, ResponseWriter, ServeMux

### Community 31 - "SwarmGuard Core Docs"
Cohesion: 0.18
Nodes (11): Federated Node Config Example, Hybrid Transport Mode, Federation Import Discount, Good-Neighbour Resource Budget, SwarmGuard README, Anti-Poisoning by Structure, Decentralised Federated IP Blocklist (Core Concept), Federated Trust Model (+3 more)

### Community 32 - "libp2p Cluster Tests"
Cohesion: 0.33
Nodes (10): localOpts(), startCluster(), TestDHTDiscoveryViaRelay(), TestStarTopologyGossipForward(), TestStarTopologyGossipSymmetric(), Context, Node, NodeMode (+2 more)

### Community 33 - "API Server Unit Tests"
Cohesion: 0.29
Nodes (7): TestBroadcastDisabled(), TestBroadcastToSubscriber(), TestNew(), TestUnsubscribeClosesChan(), stubStore, ScoreRecord, T

### Community 34 - "Honeypot Deploy (Cowrie + OpenCanary)"
Cohesion: 0.29
Nodes (10): Honeypot Sensor Strategy — watch to maximise attacker data collection, Honeypot Config, Cowrie SSH Honeypot Ingest, OpenCanary SMTP/IMAP Honeypot Ingest, Honeypot as Sensor Node (high block_threshold), Honeypot Docker Compose (Cowrie + OpenCanary + SwarmGuard), Cowrie SSH Honeypot Service (Docker), OpenCanary Honeypot Service (Docker) (+2 more)

### Community 35 - "CrowdSec Sink Tests"
Cohesion: 0.31
Nodes (9): CrowdSecSink, mockLAPI(), TestCrowdSecSink_Block(), TestCrowdSecSink_StartFail(), TestCrowdSecSink_Unblock(), Request, ResponseWriter, Server (+1 more)

### Community 36 - "Changelog & Architecture"
Cohesion: 0.31
Nodes (9): Wire SchemaVersion 0→1 Bump (additive PeerCert), Grafana Dashboard Provisioning Config, Grafana SQLite Datasource (frser-sqlite-datasource), CHANGELOG, Observability Plane (dual-output Observer), Six Prometheus Metrics, Social Trust Anchors (spec §5.1), SQLite Event History Tables (+1 more)

### Community 37 - "Reputation Store Engine"
Cohesion: 0.31
Nodes (6): BadgerStore, Duration, ScoreRecord, Engine, New(), weightFor()

### Community 38 - "BadgerDB Store Tests"
Cohesion: 0.50
Nodes (8): BadgerStore, T, openTestStore(), TestDeleteScore(), TestGetScoreMissing(), TestPutGetRoundTrip(), TestScanScores(), TestScoreRecordTrustFieldsRoundTrip()

### Community 39 - "Gossip Protocol Tests"
Cohesion: 0.42
Nodes (8): Node, NodeMode, Options, T, connect(), testOpts(), TestSubscribeSurfacesVerifiedPublisher(), TestTwoNodeGossip()

### Community 40 - "Client Library Tests"
Cohesion: 0.43
Nodes (7): TestBlocklist(), TestBlocklist_WithOpts(), TestBlocklist_WithOpts_NoFilters(), TestEvents(), TestScoreIP_Found(), TestScoreIP_NotFound(), T

### Community 41 - "Corroboration Score Tests"
Cohesion: 0.54
Nodes (7): Engine, T, openEngine(), TestRecordIncreasesScore(), TestSameReporterDoesNotIncreaseCorroboration(), TestScoreNeverExceeds100(), TestTwoReportersIncreasesCorroboration()

### Community 42 - "Wire Protocol Messages"
Cohesion: 0.36
Nodes (7): PeerCert, Time, AnchorEntry, Event, PeerCert, ScoreEntry, WhitelistEntry

### Community 43 - "DNSBL Design & Plan"
Cohesion: 0.38
Nodes (7): DNSBL Server Implementation Plan, DNSBLConfig, Embedded DNSBL DNS Server, DNSBL StoreReader Interface, DNSBL Server Design Spec, DNSBL Reversed-IP Query Format, DNSBL Response Logic (A/TXT/NXDOMAIN)

### Community 44 - "Wire Protocol Tests"
Cohesion: 0.53
Nodes (5): T, TestEventLegacyDecode(), TestEventVouchRoundTrip(), TestEventWithoutVouchOmitsField(), TestSchemaVersionBumped()

### Community 45 - "Mailcow Sensor Plan"
Cohesion: 0.50
Nodes (5): Injectable logFetcher Interface, MailcowLogs Ingest Adapter, Mailcow Self-Sufficient Sensor Implementation Plan, SMTP/IMAP Reputation Weights, Spamtrap File-Tail Ingest Adapter

### Community 47 - "SSE Events Handler"
Cohesion: 0.50
Nodes (3): Server, Request, ResponseWriter

### Community 48 - "API Score Handler"
Cohesion: 0.50
Nodes (3): Server, Request, ResponseWriter

## Knowledge Gaps
- **186 isolated node(s):** `FlagSet`, `Config`, `PublicKey`, `PeerCert`, `Time` (+181 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **9 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `New()` connect `Node Orchestration & Enforce Sinks` to `Person Identity & Trust Crypto`, `BadgerDB Reputation Engine`, `CrowdSec Ingest Adapter`, `Mailcow Log Ingest`, `BurstStore Sliding Window`, `Spamtrap File-Tail Ingest`?**
  _High betweenness centrality (0.163) - this node is a cross-community bridge._
- **Why does `Open()` connect `BadgerDB Reputation Engine` to `Person Identity & Trust Crypto`, `Corroboration Score Tests`, `Node Orchestration & Enforce Sinks`, `BadgerDB Store Tests`?**
  _High betweenness centrality (0.153) - this node is a cross-community bridge._
- **Why does `testNode()` connect `Person Identity & Trust Crypto` to `Config & Defaults`, `BadgerDB Reputation Engine`, `BurstStore Sliding Window`?**
  _High betweenness centrality (0.111) - this node is a cross-community bridge._
- **Are the 33 inferred relationships involving `GeneratePersonKey()` (e.g. with `TestAnchoredPersonCountsOnce()` and `TestExpiredVouchIsStranger()`) actually correct?**
  _`GeneratePersonKey()` has 33 INFERRED edges - model-reasoned connections that need verification._
- **Are the 27 inferred relationships involving `IssueCert()` (e.g. with `TestAnchoredPersonCountsOnce()` and `TestExpiredVouchIsStranger()`) actually correct?**
  _`IssueCert()` has 27 INFERRED edges - model-reasoned connections that need verification._
- **Are the 27 inferred relationships involving `PersonPub()` (e.g. with `TestAnchoredPersonCountsOnce()` and `TestExpiredVouchIsStranger()`) actually correct?**
  _`PersonPub()` has 27 INFERRED edges - model-reasoned connections that need verification._
- **Are the 25 inferred relationships involving `EncodePub()` (e.g. with `TestAnchoredPersonCountsOnce()` and `TestExpiredVouchIsStranger()`) actually correct?**
  _`EncodePub()` has 25 INFERRED edges - model-reasoned connections that need verification._