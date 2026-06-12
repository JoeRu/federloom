# Graph Report - .  (2026-06-12)

## Corpus Check
- Corpus is ~37,749 words - fits in a single context window. You may not need a graph.

## Summary
- 421 nodes · 595 edges · 56 communities (37 shown, 19 thin omitted)
- Extraction: 88% EXTRACTED · 12% INFERRED · 0% AMBIGUOUS · INFERRED: 71 edges (avg confidence: 0.82)
- Token cost: 164,320 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Trust & Enforcement Spec|Trust & Enforcement Spec]]
- [[_COMMUNITY_Deployment & Dev Workflow|Deployment & Dev Workflow]]
- [[_COMMUNITY_Adversarial Test Suite|Adversarial Test Suite]]
- [[_COMMUNITY_Ingest Adapters|Ingest Adapters]]
- [[_COMMUNITY_Config & Validation|Config & Validation]]
- [[_COMMUNITY_Node Orchestration|Node Orchestration]]
- [[_COMMUNITY_P2P Transport Layer|P2P Transport Layer]]
- [[_COMMUNITY_Reputation Engine|Reputation Engine]]
- [[_COMMUNITY_Architecture & Scaling|Architecture & Scaling]]
- [[_COMMUNITY_Integration Tests|Integration Tests]]
- [[_COMMUNITY_BadgerDB Store|BadgerDB Store]]
- [[_COMMUNITY_Kademlia DHT|Kademlia DHT]]
- [[_COMMUNITY_Cluster Integration Tests|Cluster Integration Tests]]
- [[_COMMUNITY_Transport Node Types|Transport Node Types]]
- [[_COMMUNITY_Ipset Enforcement Backend|Ipset Enforcement Backend]]
- [[_COMMUNITY_Ingest Plugin Registry|Ingest Plugin Registry]]
- [[_COMMUNITY_Federation Trust Model|Federation Trust Model]]
- [[_COMMUNITY_Reputation Corroboration Tests|Reputation Corroboration Tests]]
- [[_COMMUNITY_Store Unit Tests|Store Unit Tests]]
- [[_COMMUNITY_Wire Protocol Types|Wire Protocol Types]]
- [[_COMMUNITY_Peer Identity & Keys|Peer Identity & Keys]]
- [[_COMMUNITY_Ingest Plugin Interface|Ingest Plugin Interface]]
- [[_COMMUNITY_Smoke Test Scripts|Smoke Test Scripts]]
- [[_COMMUNITY_Whitelist Scoping|Whitelist Scoping]]
- [[_COMMUNITY_Honeypot Bootstrap|Honeypot Bootstrap]]
- [[_COMMUNITY_Transport Options Tests|Transport Options Tests]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]

## God Nodes (most connected - your core abstractions)
1. `Open()` - 18 edges
2. `Config` - 16 edges
3. `Node` - 14 edges
4. `Node` - 14 edges
5. `Reputation Core + Cowrie Ingest + Enforcement Plan (2026-06-10)` - 11 edges
6. `NewNeverBlockList()` - 10 edges
7. `Seven Non-Negotiable Invariants` - 10 edges
8. `writeLines()` - 9 edges
9. `DecayScore()` - 9 edges
10. `Engine` - 9 edges

## Surprising Connections (you probably didn't know these)
- `Never-Block Set (neverblock.go)` --semantically_similar_to--> `Local-Only Whitelist Never Federated (Invariant 3 / spec §6.2)`  [INFERRED] [semantically similar]
  .claude/skills/enforce-backend/SKILL.md → CLAUDE.md
- `Federation Import Discount` --semantically_similar_to--> `Asymmetric Trust Decay (Invariant 5 / spec §4.3)`  [INFERRED] [semantically similar]
  deploy/examples/config.federated.yaml → CLAUDE.md
- `Reputation Decay (TTL as GDPR Deletion)` --semantically_similar_to--> `IPs as Personal Data (Invariant 2 / spec §9)`  [INFERRED] [semantically similar]
  README.md → CLAUDE.md
- `Sybil Resistance via Diversity Weighting` --semantically_similar_to--> `Asymmetric Trust Decay (Invariant 5 / spec §4.3)`  [INFERRED] [semantically similar]
  .claude/skills/adversarial-test/SKILL.md → CLAUDE.md
- `Ground-Truth Anchors (Honeypots / Spamtraps)` --semantically_similar_to--> `Trust Anchors Locally Removable (Invariant 6 / spec §5.1)`  [INFERRED] [semantically similar]
  .claude/skills/add-ingest-plugin/SKILL.md → CLAUDE.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Anti-Poisoning Mechanisms: Ground-Truth Anchors + Diversity Weighting + Asymmetric Decay** — concept_ground_truth_anchors, concept_sybil_resistance, concept_asymmetric_trust_decay [EXTRACTED 0.95]
- **CI Security Gate: Adversarial Suite runs on every PR touching reputation/trust/ingest** — workflows_ci, concept_adversarial_suite, adversarial_test_skill [EXTRACTED 0.95]
- **GDPR by Design: IPs as personal data + decay-as-deletion + local admin as controller** — concept_ip_personal_data, concept_reputation_decay, concept_local_overridability [INFERRED 0.85]
- **Ingest → Reputation → Enforce Pipeline (local event flow)** — plans_reputation_core_honeypot_go, plans_reputation_core_engine_go, plans_reputation_core_neverblock, plans_reputation_core_ipset_go, plans_reputation_core_node_go [EXTRACTED 1.00]
- **Poisoning Defence Layers (ground-truth + corroboration + asymmetric decay + dispute)** — docs_spec_ground_truth_anchors, docs_spec_diversity_corroboration, docs_spec_asymmetric_decay, docs_spec_anti_trust_dispute [EXTRACTED 1.00]
- **Federation Founding Duties (ground-truth + whitelist + key management + override principle)** — onboarding_01_ground_truth_anchors, onboarding_02_whitelist_federation_mass, onboarding_03_key_management, onboarding_04_override_lists_aids [EXTRACTED 1.00]

## Communities (56 total, 19 thin omitted)

### Community 0 - "Trust & Enforcement Spec"
Cohesion: 0.06
Nodes (45): Decay as GDPR Storage Limitation, crowdsec Enforcement Backend (emit CrowdSec-compatible list), enforce.Sink Interface (plugin contract), ipset Enforcement Backend (O(1)), nftables Enforcement Backend (O(1)), Anti-Trust / Dispute Feedback (§4.4, whitelist as negative vote), Asymmetric Decay / Reputation Stake (§4.3), Diversity-Weighted Corroboration (§4.2) (+37 more)

### Community 1 - "Deployment & Dev Workflow"
Cohesion: 0.09
Nodes (43): Add Ingest Plugin Skill, Adversarial Test Skill, Invariant Guardian Agent, Client Config (Federated Peer), Client Docker Compose, Adversarial Test Suite (CI Gate), Asymmetric Trust Decay (Invariant 5 / spec §4.3), CrowdSec Interoperability (Consume + Emit) (+35 more)

### Community 2 - "Adversarial Test Suite"
Cohesion: 0.11
Nodes (21): mockSink, TestNeverBlockPoisoningLoopback(), TestNeverBlockPoisoningRFC1918(), TestNeverBlockPublicIPNotProtected(), TestSybilFloodHighTrustCapped(), TestSybilFloodScoreCapped(), NewNeverBlockList(), TestNeverBlockExtraWhitelist() (+13 more)

### Community 3 - "Ingest Adapters"
Cohesion: 0.13
Nodes (22): cowrieEvent, Honeypot, NewHoneypot(), TestHoneypotParsesLoginFailed(), TestHoneypotSkipsEmptyIP(), TestHoneypotUnknownEventID(), writeLines(), OpenCanary (+14 more)

### Community 4 - "Config & Validation"
Cohesion: 0.11
Nodes (24): Config, Defaults(), Load(), LoadYAML(), TestDefaultsAreValid(), TestDefaultsOpenCanaryPollInterval(), TestLoadYAML(), TestLoadYAMLOpenCanaryEnabled() (+16 more)

### Community 5 - "Node Orchestration"
Cohesion: 0.12
Nodes (14): Config, NewNftables(), NftablesSink, Context, BadgerStore, Context, Engine, Event (+6 more)

### Community 6 - "P2P Transport Layer"
Cohesion: 0.14
Nodes (14): CancelFunc, Context, Event, Host, IpfsDHT, Options, Node, Options (+6 more)

### Community 7 - "Reputation Engine"
Cohesion: 0.15
Nodes (15): Duration, Time, T, BadgerStore, Duration, containsString(), DecayScore(), TestDecayAtOneHalfLife() (+7 more)

### Community 8 - "Architecture & Scaling"
Cohesion: 0.15
Nodes (17): scripts/dev/docker-compose.dev.yml (bootstrap + relay + 3 leaves), Bloom Filter (negative pre-filter for DHT lookup), Control Plane (reputation, trust, store, transport), Data Plane (enforce.Sink), DHT On-Demand Lookup (DNSBL-style), Observability Plane (opt-in, default OFF), Three Planes Architecture, Relay Hierarchy (aggregator nodes, §11.4) (+9 more)

### Community 9 - "Integration Tests"
Cohesion: 0.30
Nodes (6): mockSink, TestPipelineBlockAfterThreshold(), TestPipelineNeverBlockProtected(), TestPipelineUnblockAfterDecay(), Context, T

### Community 10 - "BadgerDB Store"
Cohesion: 0.25
Nodes (5): DB, Duration, Time, BadgerStore, ScoreRecord

### Community 11 - "Kademlia DHT"
Cohesion: 0.22
Nodes (8): ID, AddrInfo, Context, Host, IpfsDHT, NodeMode, Node, buildDHT()

### Community 12 - "Cluster Integration Tests"
Cohesion: 0.33
Nodes (10): localOpts(), startCluster(), TestDHTDiscoveryViaRelay(), TestStarTopologyGossipForward(), TestStarTopologyGossipSymmetric(), Context, Node, NodeMode (+2 more)

### Community 13 - "Transport Node Types"
Cohesion: 0.25
Nodes (9): T, Node, NodeMode, Options, T, TestDHTFindPeerViaRelay(), connect(), testOpts() (+1 more)

### Community 14 - "Ipset Enforcement Backend"
Cohesion: 0.31
Nodes (3): NewIpset(), IpsetSink, Context

### Community 15 - "Ingest Plugin Registry"
Cohesion: 0.22
Nodes (9): crowdsec Ingest Adapter, fail2ban Ingest Adapter, honeypot Ingest Adapter (Cowrie, Dionaea, OpenCanary), ingest.Source Interface (plugin contract), mailcow_logs Ingest Adapter, spamtrap Ingest Adapter, Mailcow Integration (non-invasive add-on container), Honeypot Zero-False-Positive Property (+1 more)

### Community 16 - "Federation Trust Model"
Cohesion: 0.25
Nodes (8): Mastodon-Model Federation (subnet trust domains), Defederation (security lever for malicious subnets), Origin Tracing (prevents A-B double counting), Trust Discount (foreign scores weighted less than local), Phase Plan (MVP → P2P → Trust → Federation → Scaling), Open Problems and Risks (§12, A-R), Subnets / Federation (Mastodon model, trust domains, §5.2), Threat Model (adversaries and defences)

### Community 17 - "Reputation Corroboration Tests"
Cohesion: 0.54
Nodes (7): Engine, T, openEngine(), TestRecordIncreasesScore(), TestSameReporterDoesNotIncreaseCorroboration(), TestScoreNeverExceeds100(), TestTwoReportersIncreasesCorroboration()

### Community 18 - "Store Unit Tests"
Cohesion: 0.54
Nodes (7): BadgerStore, T, openTestStore(), TestDeleteScore(), TestGetScoreMissing(), TestPutGetRoundTrip(), TestScanScores()

### Community 19 - "Wire Protocol Types"
Cohesion: 0.47
Nodes (5): Time, AnchorEntry, Event, ScoreEntry, WhitelistEntry

### Community 20 - "Peer Identity & Keys"
Cohesion: 0.50
Nodes (5): AddrInfo, Multiaddr, PrivKey, NodeMode, Options

### Community 23 - "Whitelist Scoping"
Cohesion: 0.67
Nodes (3): Data Model: WhitelistEntry (§7.4, local-only vs shared-vote), Local Truth (never shared, install-script detected), Whitelist Scope Separation (local-only vs shared-vote)

## Knowledge Gaps
- **96 isolated node(s):** `Node`, `StoreConfig`, `ReputationConfig`, `IngestConfig`, `EnforceConfig` (+91 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **19 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Open()` connect `Adversarial Test Suite` to `Ingest Adapters`, `Node Orchestration`, `Integration Tests`, `BadgerDB Store`, `Reputation Corroboration Tests`, `Store Unit Tests`?**
  _High betweenness centrality (0.065) - this node is a cross-community bridge._
- **Why does `New()` connect `Node Orchestration` to `Adversarial Test Suite`, `Ingest Adapters`, `Ipset Enforcement Backend`?**
  _High betweenness centrality (0.057) - this node is a cross-community bridge._
- **Why does `NewNeverBlockList()` connect `Adversarial Test Suite` to `Integration Tests`, `Node Orchestration`?**
  _High betweenness centrality (0.018) - this node is a cross-community bridge._
- **Are the 16 inferred relationships involving `Open()` (e.g. with `TestNeverBlockPoisoningLoopback()` and `TestNeverBlockPoisoningRFC1918()`) actually correct?**
  _`Open()` has 16 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Node`, `StoreConfig`, `ReputationConfig` to the rest of the system?**
  _105 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Trust & Enforcement Spec` be split into smaller, more focused modules?**
  _Cohesion score 0.06464646464646465 - nodes in this community are weakly interconnected._
- **Should `Deployment & Dev Workflow` be split into smaller, more focused modules?**
  _Cohesion score 0.09191583610188261 - nodes in this community are weakly interconnected._