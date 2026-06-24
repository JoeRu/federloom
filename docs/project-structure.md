# Projektstruktur-Vorschlag: P2P-Reputations-Blockliste

**Bezug:** `p2p-blocklist-spec.md`
**Arbeitstitel (Platzhalter im Pfad):** `federloom` (final offen – s. Spec)
**Layout:** Monorepo, Go, libp2p

---

## 1. Technik-Entscheidungen (Annahmen)

| Bereich | Wahl | Begründung | Alternative |
|---------|------|------------|-------------|
| Sprache | **Go** | Ein statisches Binary, reife Krypto-Stdlib, einfache Docker-Paketierung, gute Nebenläufigkeit | Rust (mehr Performance/Sicherheit, steiler) |
| P2P-Substrat | **libp2p** | Gossipsub (Control-Plane), Kademlia-DHT (On-Demand-Lookup §11.4), Peer-Identität, Noise-Verschlüsselung, NAT-Traversal – erprobt durch IPFS/Ethereum | eigenes Gossip-Protokoll (mehr Kontrolle, viel Arbeit) |
| Speicher | **BadgerDB** (embedded KV) | keine externe DB, schnelle Schreiblast, TTL-Support passt zu Decay | SQLite (relational, einfacher zu inspizieren) |
| Vorfilter | **In-Memory Bloom-Filter** | kompakte Negativ-Antworten (§11.3) | Cuckoo-Filter (löschbar) |
| Enforcement | **ipset / nftables** via netlink | O(1)-Lookups (§11.3), kein iptables-Regel-pro-IP | nftables-Sets nativ |
| Config | **YAML + ENV-Override** | menschenlesbar, gut für Docker | TOML |

> Repo-Modulpfad im Beispiel: `github.com/<org>/federloom`

---

## 2. Architektur → Repo-Mapping

Die Drei-Ebenen-Architektur (§11.2) und die Trust-Primitive (§5) sind als getrennte
Pakete sichtbar:

- **Data Plane** → `internal/enforce`
- **Control Plane** → `internal/reputation`, `internal/transport`, `internal/store`
- **Observability Plane** → `internal/observability`
- **Trust/Föderation** → `internal/trust`
- **Ground-Truth-Ingest** → `internal/ingest`
- **Onboarding-Pflichten (§6)** → `scripts/install`, `cmd/federloomctl`, `docs/onboarding`

---

## 3. Verzeichnisbaum

```
federloom/
├── README.md                     # Einstieg + Verweis auf Onboarding (§6 prominent!)
├── LICENSE
├── CHANGELOG.md
├── go.mod / go.sum
├── Makefile                      # build, test, lint, release
│
├── cmd/                          # ausführbare Binaries
│   ├── federloomd/                   # der P2P-Node-Daemon (Long-running)
│   │   └── main.go
│   └── federloomctl/                 # Admin-CLI (Keys, Anchors, Föderation, Status)
│       └── main.go
│
├── internal/                     # private Anwendungslogik (nicht importierbar)
│   ├── node/                     # Orchestrierung: verdrahtet alle Subsysteme
│   │
│   ├── identity/                 # Knoten-Schlüssel, Signieren/Verifizieren (§6.3)
│   │   ├── keys.go
│   │   └── rotation.go           # Rotation, Revocation
│   │
│   ├── transport/                # libp2p: Gossipsub + Kademlia-DHT (§5, §11.4)
│   │   ├── gossip.go             # Control-Plane: Score-/Event-Verbreitung
│   │   ├── dht.go                # On-Demand-Lookup (DNSBL-Modell)
│   │   └── relay.go              # Relay-/Aggregator-Rolle (§11.4)
│   │
│   ├── reputation/               # Kern-Scoring-Engine (Control Plane)
│   │   ├── score.go              # Normalisierung, Eskalation
│   │   ├── decay.go              # asymmetrischer Decay (§4.3, §8)
│   │   ├── corroboration.go      # Diversitäts-Gewichtung (§4.2)
│   │   └── dispute.go            # Anti-Trust / Whitelist-Votes (§4.4)
│   │
│   ├── trust/                    # Föderation & Trust-Anchors (§5)
│   │   ├── anchors.go            # Trust-Anchor-Liste (lokal ergänz-/entfernbar!)
│   │   ├── federation.go         # Import mit Trust-Discount, Herkunfts-Tracking
│   │   ├── defederation.go       # Sicherheits-Defederation
│   │   └── webtrust.go           # (optional) Bürgschaft / Web-of-Trust
│   │
│   ├── ingest/                   # Event-Quellen → Meldungen (§4.1, §6.1)
│   │   ├── mailcow_logs.go       # SMTP-AUTH-Bruteforce etc. aus Mailcow-Logs
│   │   ├── spamtrap.go           # Honeypot-Semantik im Echtsystem (§6.1)
│   │   ├── honeypot.go           # dedizierte Honeypots
│   │   └── fail2ban_crowdsec.go  # vorhandene Detektoren als Quelle
│   │
│   ├── store/                    # Persistenz + Vorfilter (§11.3)
│   │   ├── badger.go             # Reputations-DB (TTL → Decay-GC)
│   │   ├── bloom.go              # kompakter Negativ-Vorfilter
│   │   └── whitelist.go          # local-only vs. shared-vote (§6.2/§7.4)
│   │
│   ├── enforce/                  # Data Plane: Durchsetzung (§11.3)
│   │   ├── ipset.go              # ipset-Backend (O(1))
│   │   ├── nftables.go           # nftables-Backend
│   │   └── neverblock.go         # Pflicht-Schutzliste (§10)
│   │
│   ├── api/                      # lokale API → Outputs (§3)
│   │   ├── score.go              # Reputations-Score pro IP (Default)
│   │   ├── blocklist.go          # fertige Blockliste (Fail2Ban/CrowdSec-drop-in)
│   │   └── events.go             # Roh-Events
│   │
│   ├── observability/            # Observability Plane (Opt-in, default AUS! §11.2)
│   │   ├── firehose.go           # Echtzeit-Eventstream (Angriffswellen-Monitoring)
│   │   └── metrics.go            # Prometheus-Metriken
│   │
│   ├── resources/                # Gutes-Nachbar-Prinzip (§11.5)
│   │   ├── budget.go             # CPU-/Bandbreiten-Limit
│   │   └── degrade.go            # Lastabwurf / graceful degradation
│   │
│   └── config/                   # Config-Laden, Defaults, ENV-Override
│       └── config.go
│
├── pkg/                          # öffentlich importierbare, stabile Typen
│   ├── proto/                    # Wire-Format: Event, ScoreEntry, AnchorEntry (§7)
│   │   └── messages.go
│   └── client/                   # Go-Client für die lokale API
│
├── scripts/
│   ├── install/                  # Installations-Script (§6.2)
│   │   ├── install.sh
│   │   └── detect_local_truth.sh # eigene IP, GW, DNS, Docker-Ranges → local-only WL
│   └── dev/                      # Dev-Helfer (lokales Testnetz hochziehen)
│
├── deploy/
│   ├── docker/
│   │   ├── Dockerfile
│   │   └── docker-compose.yml    # Standalone-Deployment
│   ├── mailcow/                  # Mailcow-Add-On-Integration
│   │   ├── docker-compose.override.yml
│   │   └── README.md             # wie ins Mailcow-Setup einklinken
│   └── examples/                 # Beispiel-Konfigurationen
│       ├── config.solo.yaml      # Einzelknoten
│       ├── config.federated.yaml # föderiert (mit Discount)
│       └── config.isolated.yaml  # eigenes isoliertes Teilnetz
│
├── docs/
│   ├── spec.md                   # die Spezifikation
│   ├── onboarding/               # §6: Gründungspflichten je Föderation – PROMINENT
│   │   ├── 01-ground-truth.md    # Anchor-Systeme setzen (§6.1)
│   │   ├── 02-whitelist.md       # Massen-Whitelist + lokale Wahrheit (§6.2)
│   │   ├── 03-key-management.md  # Schlüssel-Management (§6.3)
│   │   └── 04-override.md        # Listen sind Hilfsmittel, kein Gesetz (§6.4)
│   ├── threat-model.md           # Poisoning, Sybil, Privacy-Leaks (Risiken §12)
│   ├── architecture.md           # Drei-Ebenen-Modell, Datenflüsse (§11)
│   ├── federation-guide.md       # Teilnetz aufsetzen / föderieren / defederieren
│   └── api.md                    # lokale API-Referenz
│
├── test/
│   ├── integration/              # Mehrknoten-Tests (Gossip, Korroboration)
│   └── adversarial/              # Poisoning-/Sybil-Szenarien als Tests
│
└── .github/
    └── workflows/                # CI: build, test, lint, adversarial-suite, release
```

---

## 4. Komponenten-Verantwortlichkeiten (Kurz)

- **`cmd/federloomd`** – der laufende Daemon: zieht Ingest → Reputation → Enforce
  zusammen und spricht über `transport` mit dem Netz.
- **`cmd/federloomctl`** – Admin-Werkzeug: Schlüssel erzeugen/rotieren, Anchors
  hinzufügen/entfernen, Teilnetze föderieren/defederieren, Status/Score abfragen.
- **`internal/trust`** – das vereinheitlichende Primitiv: Honeypot-Anker,
  Projekt-Defaults und Never-Block-Set sind hier dieselbe Mechanik mit anderem
  Gewicht/Quelle (vgl. Spec §5.1).
- **`internal/enforce`** – die einzige Stelle, die in die Firewall schreibt;
  bewusst klein und isoliert, weil sicherheitskritisch.
- **`scripts/install`** – sicherheitskritisch: schreibt die local-only-Whitelist.
  Konservativ defaulten, erkannte Einträge dem Admin zur Bestätigung vorlegen.
- **`internal/observability`** – komplett optional und default deaktiviert, damit
  der Normalbetrieb nie durch den Firehose belastet wird.

---

## 5. Mailcow-Integration

- Add-On als **eigener Container** neben dem Mailcow-Stack
  (`deploy/mailcow/docker-compose.override.yml`), keine Forks der Mailcow-Images.
- **Ingest** liest Mailcow-/Postfix-/Dovecot-Logs (read-only) für Angriffssignale.
- **Enforce** setzt `nftables`/`ipset`-Sets, die Mailcow-Border (bzw. der Host)
  konsultiert – bzw. liefert eine Blockliste, die der vorhandene Fail2Ban-Container
  konsumiert (drop-in, §3).
- Kein Eingriff in Mailcows Update-Zyklus → Add-On bleibt unabhängig aktualisierbar.

---

## 6. Phasenplan (folgt Spec §13)

1. **MVP / Single-Node:** `ingest` (Mailcow-Logs + Spamtrap) → `reputation` →
   `enforce` (ipset). Noch ohne Netz. Liefert sofort lokalen Nutzen.
2. **P2P-Kern:** `transport` (Gossipsub) + `store` (Bloom) +
   Diversitäts-Korroboration. Trägt laut Spec ~80 % der Last.
3. **Trust-Anchors:** `trust/anchors` + Schlüssel-Lebenszyklus (`identity`).
4. **Föderation:** `trust/federation` + `defederation` + DHT-On-Demand-Lookup.
5. **Skalierung/Härtung:** Relay-Rolle, Ressourcen-Budget, Lastabwurf,
   Observability-Plane.

---

## 7. Repo-Konventionen (Empfehlung)

- **`internal/` strikt nutzen** – verhindert, dass instabile Interna von Dritten
  importiert werden; nur `pkg/` ist öffentlicher Vertrag.
- **`adversarial/`-Testsuite als CI-Gate** – Poisoning-/Sybil-Szenarien laufen bei
  jedem PR; Sicherheit ist hier ein Feature, kein Nachgedanke.
- **Conventional Commits + SemVer** für nachvollziehbare Releases.
- **Onboarding-Docs im selben PR wie das Feature** – die §6-Pflichten verfallen
  sonst; Doku ist Teil der „Definition of Done".
