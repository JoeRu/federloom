# Spezifikation: Dezentrale P2P-Reputations-Blockliste

**Arbeitstitel:** *FederLoom* / https://github.com/JoeRu/federloom
**Status:** Aktuelle Implementierung in Arbeit / Aktueller Stand
**Primärer Anwendungsfall:** Gemeinsame Verteidung durch geteilte Informationen / https://github.com/JoeRu/Mailcow-Crowdsec-Override
**Datum:** 2026-07-07

---

## 1. Zielsetzung

Ein dezentrales Peer-to-Peer-Netz, in dem Server (initial: Mailserver) beobachtete
Angriffe melden und gemeinsam einen **Reputations-Score pro IP-Adresse** aufbauen.
Jeder Betreiber bleibt souverän: Er konsumiert den Score und entscheidet anhand
**eigener Schwellwerte und Whitelists** lokal über Sperren.

Inspiriert von Torrent-/Tor-/Ethereum-Konzepten (Gossip-Verteilung, kein zentraler
Single-Point-of-Failure, ökonomisch/reputativ verankertes Vertrauen), aber bewusst
**ohne echte Blockchain und ohne Token/Geld** gehalten – so einfach wie möglich,
so funktional wie nötig.

---

## 2. Leitprinzipien

1. **Lokale Souveränität zuerst.** Das Netz liefert ein *Signal* (Score), keine
   bindende Anweisung. Schwellen, Whitelists und Block-Aktionen entscheidet der Admin.
2. **Vertrauen ist verdient, nicht gegeben.** Trust wächst langsam, fällt schnell.
3. **Strukturelle Angriffseigenschaften ausnutzen.** Echte Angriffe sind *breit
   gestreut* und *unabhängig*; Poisoning ist es nur unter hohen Kosten.
4. **Eventual Consistency.** Kein globaler Konsens nötig – Gossip/DHT-artige
   Verbreitung, lokale Sicht ist die Wahrheit.
5. **DSGVO by Design.** Rechtsgrundlage berechtigtes Interesse + automatische
   Löschung via Decay + Verantwortlichkeit beim lokalen Admin.
6. **Föderiertes Vertrauen.** Trust spiegelt soziale/organisatorische Strukturen
   wider (Mastodon-Modell). Kein globaler Trust-Zwang; Teilnetze und Trust-Anchors
   sind lokal wähl- und widerrufbar.
7. **Listen sind Hilfsmittel, kein Gesetz.** Der Nutzer kann **einzelne oder alle
   Parameter überschreiben**. Block- und Allow-Listen sind „nur" ein Hilfsmittel –
   die finale Entscheidung liegt immer lokal.
8. **Lokal souverän, remote nur beratend.** Der Operator darf lokal **alles**
   tunen (Whitelists, Peer-/Föderations-Trust, Regeln). Die harte Invariante gilt
   **gegenüber dem Netz**: kein importiertes Signal, kein Peer, keine Föderation darf
   bei dir einen Block, eine Whitelist- oder eine Trust-Änderung **erzwingen** —
   Remote-Input ist immer *beratend*. Sichere Defaults werden ausgeliefert;
   Runtertunen geschieht auf eigenes Risiko. (Schärft #1/#7 gegen Netzwerk-Poisoning.)

---

## 3. Outputs (für Konsumenten)

Drei Abstraktionsebenen, je nach Anwendungsfall:

| Ebene | Beschreibung | Zielgruppe |
|-------|--------------|------------|
| **Reputations-Score pro IP** *(Default)* | Normalisierter Wert (z. B. 0–100) | Die meisten Admins |
| **Fertige Blockliste** | Score + lokaler Threshold → drop-in für Fail2Ban/CrowdSec | „Plug & Play"-Admins |
| **Roh-Events** | Einzelmeldungen mit Evidenz | Power-User / eigene Auswertung |
| **Föderations-Feed-Export (STIX/TAXII)** | Client *liest* die Föderation und publiziert Events downstream (SIEM/TIP) | Integratoren |

Decay und Eskalation sind **Funktionen des Scores**, keine harten An/Aus-Regeln.

Der STIX/TAXII-Export ist **Egress über die bestehende REST-API** (Poll-Modell,
downstream pollt — kein Push-Connector). STIX `confidence`/`valid_until` mappen auf
Score/Decay; das Szenario (§7.1) auf STIX `attack-pattern`. **Eigene Reason-Codes
bleiben Source of Truth**, STIX-Mapping nur an der Kante.

---

## 4. Verteidigungs-Stack gegen Poisoning (Kern des Designs)

Gewählter **schlanker Stack** – drei Schichten tragen ~80 % der Last:

### 4.1 Ground-Truth-Anchor-Systeme
- Quellen unbestechlicher Wahrheit, maximal gewichtet (Trust ≈ 1.0). Zwei Bauformen,
  Detail-Pflichten je Föderation in §6.1:
  - **Dedizierte Honeypots:** IPs/Mailboxen, die **niemals legitim genutzt** werden →
    jede Verbindung ist per Definition bösartig → **null False Positives**.
  - **Echtsysteme unter Last** mit **honeypot-artigen Signalen** (Spamtraps,
    Auth gegen nicht existierende Accounts, ungenutzte Ports).
- Doppelnutzen:
  - **Bootstrapping/Genesis-Trust** (löst das Henne-Ei-Problem neuer Knoten).
  - **Kalibrierung:** Knoten, die bekannte Ground-Truth-Angreifer *nicht* melden oder
    Ground-Truth-IPs whitelisten, verlieren Trust.
- **Betriebsmodelle (beide dokumentiert, wählbar):**
  - **A) Zentral:** Projekt betreibt Anker + signiert Genesis-Peers. → einfacher
    Start, klarer Trust-Anchor, aber zentrale Abhängigkeit.
  - **B) Dezentral:** Freiwillige betreiben Anker, deren Status wird im Netz
    attestiert. → robuster, aber komplexere Verifikation nötig.

### 4.2 Diversitäts-gewichtete Korroboration
- Score steigt erst, wenn **N *unabhängige* Melder** dieselbe IP sehen.
- Unabhängigkeit zählt, nicht Anzahl: Gewichtung nach **Diversität der Quellen**
  (verschiedene ASNs, Länder, Trust-Herkunft).
  - 10 Meldungen aus *einem* ASN ≈ 1 Stimme.
  - 10 Meldungen aus 10 Ländern = echtes Signal.
- Nutzt die strukturelle Eigenschaft echter Angriffe (breit, unabhängig); Fälschung
  erfordert teure, breit verteilte Angreifer-Infrastruktur.

### 4.3 Reputation-Stake mit asymmetrischem Decay
- **Kein Geld/Token** – auf dem Spiel steht der über Zeit aufgebaute **Trust**.
- Trust-Formel (Richtung):
  `Trust = f(Alter × nachgewiesene legitime Aktivität × Konsens-Übereinstimmung)`
  - **Wichtig:** Alter *allein* ist Sybil-anfällig (*patient Sybil*: Knoten 6 Monate
    brav laufen lassen, dann koordiniert aktivieren). Alter daher **nur in Kopplung**
    an Aktivität und Konsens-Übereinstimmung werten.
- **Asymmetrie als Sicherheit:** Trust steigt **langsam**, fällt **schnell** bei
  Anomalie oder Dispute (Schutz gegen gekaperte High-Trust-Knoten, die plötzlich
  z. B. `8.8.8.8` melden).

### 4.4 Anti-Trust / Dispute-Rückkopplung (ergänzend)
- **Lokale Whitelist = negativer, trust-gewichteter Vote.** Whitelisten viele Admins
  eine IP, ist das ein starkes „legitim"-Signal.
- Meldet ein Knoten wiederholt breit-whitelistete IPs, sinkt **sein eigener Trust**
  → Poisoning beschädigt den Poisoner.
- **Achtung Gegenangriff:** Massen-Whitelisting durch Sybils könnte echte Angreifer
  schützen → Whitelist-Votes brauchen **dieselbe Diversitäts-/Trust-Gewichtung** wie
  Block-Votes.

> **Optional / spätere Ausbaustufe (nicht im schlanken Stack):**
> Proof-of-Work pro Meldung als Flut-Bremse; Web-of-Trust mit Bürgschaft;
> Reputation-Slashing; strukturierte Plausibilitätsprüfung der Evidenz.

### 4.5 Applicability-Gewichtung (lokal, consume-time)
- Beim **Konsumieren** wird ein Signal danach gewichtet, wie **anwendbar** der
  angegriffene Dienst auf das *eigene* System ist (System-Profil §7.6, ggf.
  SBOM-abgeleitet). Ein `ssh-brute-force`-Signal wiegt für einen SSH-exponierten
  Peer mehr.
- **Soft down-weight, kein Hard-Filter** (Default): Dienste ändern sich, Angreifer
  pivotieren, und die IP bleibt für die Korroboration wertvoll. Hartes Filtern nur
  als optionale lokale Policy.
- **Rein lokale Transformation:** ändert die *geteilte* Reputation nicht → die
  Föderations-Konsistenz bleibt erhalten, während jeder Peer auf das Relevante
  reagiert.
- Resultierende lokale Formel:
  `effektives Gewicht = Korroboration × Source-Trust × lokale-Anwendbarkeit`.

---

## 5. Föderation, Trust-Anchors & Teilnetze

Verschiebt das System von *einem* globalen Trust-Graphen zu **föderierten
Trust-Domänen** – konsistent mit Leitprinzip 4 (lokale Sicht ist Wahrheit) und dem
**Mastodon-Modell** föderierter sozialer Netze mit eigenen Vertrauensmitteln.

### 5.1 Trust-Anchor-Liste (signaturbasiert)
- Lokal kuratierbare Liste vertrauenswürdiger **Signaturschlüssel** (Trust Anchors).
- Eine Meldung/ein Score von einem Anchor – oder von jemandem, den ein Anchor
  verbürgt – erhält **erhöhtes Gewicht**.
- Das Projekt kann über **organisatorische Maßnahmen** vertrauenswürdige Signaturen
  bereitstellen/verteilen, z. B.:
  - signierte „bekannte gute Betreiber",
  - Ground-Truth-Anchor-Betreiber (Brücke zu §4.1),
  - kuratierte CERT-/Threat-Intel-Feeds.
- **Kritisch – gegen Re-Zentralisierung:** Anchors müssen lokal **ergänz- UND
  entfernbar** sein. Projekt-Anchors sind sinnvoller **Default, kein Zwang**.
  Andernfalls wird das Projekt durch die Hintertür zur zentralen Autorität.
- **Schlüssel-Lebenszyklus:** Rotation, Revocation (Revocation-Liste bzw. kurze
  Gültigkeiten), Umgang mit kompromittierten Anchor-Keys (Details §6.3).
- **Vereinheitlichendes Primitiv:** Honeypot-/Ground-Truth-Anker (§4.1) und das
  Never-Block-Set (§10) sind Spezialfälle dieser Anchor-Mechanik – gleiche Logik,
  unterschiedliches Gewicht und unterschiedliche Quelle.

### 5.2 Eigene Teilnetze (Federation, Mastodon-Modell)
- Betreiber können **eigene Trust-Domänen/Teilnetze** mit eigenen Trust-Wurzeln und
  eigener Governance aufspannen.
- **Analogie Mastodon:** jede Instanz moderiert selbst, föderiert aber selektiv.
- Betriebsarten eines Teilnetzes:
  - **Isoliert:** eigener Trust, kein Import (z. B. Firmen-/Verbund-internes Netz).
  - **Föderiert:** es werden **Evidenz-Aggregate** (nicht fertige Scores) anderer
    Teilnetze importiert und **lokal regelbasiert neu berechnet**. Der frühere
    Trust-Discount wird zum **Evidenz-Gewicht** pro Quelle/Subnetz. Damit entfällt
    das Problem, fremde Score-Skalen zu kombinieren (vgl. Matrix MSC3845, das genau
    daran als Draft hängt — s. `docs/prior-art.md`).
- **Föderationsmodus** (wie Mastodon):
  - **Allowlist / default-deny:** nur explizit vertraute Teilnetze.
  - **Blocklist / default-allow:** alle außer explizit geblockten.
  - *Empfehlung:* Föderation als Default (mit Discount), Isolation als bewusste
    Ausnahme – sonst zersplittert die Abdeckung vor dem Netzwerkeffekt.
- **Defederation als Sicherheitsmechanismus:** ein bösartiges/kompromittiertes
  Teilnetz wird wie eine schlechte Mastodon-Instanz „defederiert" → die Sybil-Antwort
  auf **Teilnetz-Ebene**.
- **Achtung Rückkopplung:** Gegenseitiger Import (A↔B) kann dieselbe Information
  mehrfach zählen lassen → **Herkunfts-Tracking** pro Meldung oder streng abklingender
  Discount über Föderations-Hops nötig (Problem K).

### 5.3 Resultierendes Modell
- Statt *einer* globalen Wahrheit ein **Geflecht von Trust-Domänen**, das soziale und
  organisatorische Vertrauensstrukturen abbildet.
- Jeder Knoten/jedes Teilnetz berechnet seinen **eigenen** Score aus:
  `eigene Evidenz + importierte (evidenz-gewichtete) fremde Evidenz + Anchor-Signale`,
  lokal über die Regel-Engine zu einem **eigenen** Score verrechnet.

---

## 6. Organisatorische Pflichten je Föderation (Onboarding & Repo-Doku)

Jede Föderation/Gruppe muss diese Punkte **initial ausprägen**; beitretende Nutzer
fordern einen sinnvollen Anschluss daran. **Das Repository MUSS dies klar erklären**
(prominenter Onboarding-Guide, nicht nur Referenz-Anhang).

### 6.1 Ground-Truth-Anchor-Systeme festlegen
- Eintragung der entsprechenden **Signaturen als hoch gewichtete Trust-Anchors** (§5.1).
- Quelle wahlweise:
  - **Dedizierte Honeypots** – Null False Positives, aber Extra-Infrastruktur.
  - **„Echte Systeme unter Last"** – sehen reale Angriffsmuster, keine Extra-Box nötig.
- **Kritischer Caveat:** Ein Echtsystem hat **keine** Null-False-Positive-Eigenschaft
  (es empfängt auch legitimen Traffic). Empfehlung: nicht das ganze System als Ground
  Truth werten, sondern **honeypot-artige Signale innerhalb des Echtsystems**, die die
  Garantie bewahren:
  - Spamtrap-Adressen (nie real genutzte Mailboxen),
  - Auth-Versuche gegen nicht existierende Accounts,
  - Verbindungen auf ungenutzte/geschlossene Ports.

### 6.2 Massen-Whitelist pflegen (zentral + lokale Wahrheit)
- Föderations-weite Whitelist (entspricht Never-Block-Set, §10) wird zentral gepflegt.
- **Ergänzt immer um die „lokale Wahrheit"** je Installation, idealerweise per
  **Installationsscript**, das automatisch ausliest und listet:
  - eigene öffentliche IP(s),
  - Gateways,
  - eigene/konfigurierte DNS-Server,
  - lokale Docker-IP-Ranges (z. B. Bridge-Netze 172.16.0.0/12),
  - RFC1918 / Loopback.
- **Zwingende Trennung (Privacy, Problem E):**
  - **Lokal-only-Whitelist:** lokale Infrastruktur – wird **nie ins Netz geteilt**
    (irrelevant für andere + leakt Topologie). Unterdrückt nur lokale Blocks.
  - **Geteilte Whitelist-Votes:** bewusste „diese öffentliche IP ist legitim"-Signale
    (trust-gewichtet, §4.4).
- **Caveat Auto-Detection:** darf nicht zu breit whitelisten (z. B. ganze öffentliche
  Provider-Ranges) → konservativ, nur eindeutig lokale Bereiche.
- → adressiert **Problem F**.

### 6.3 Schlüssel-Management
- Festlegen, **wer Anchor-/Knoten-Schlüssel ausgibt und verbürgt**.
- Rotation- und Revocation-Policy: Verteilung der Revocation-Liste, Gültigkeitsdauern.
- Verfahren für **kompromittierte Schlüssel**: schneller Widerruf + Trust-Reset.
- → adressiert **Problem J**.

### 6.4 Übergeordnetes Prinzip (Erinnerung)
Der Nutzer kann am Ende **einzelne oder alle Parameter überschreiben**. Die Listen
(Block & Allow) sind **„nur" ein Hilfsmittel** – siehe Leitprinzip 7. Das Onboarding
muss dies explizit machen, damit niemand die Föderations-Defaults für bindend hält.

---

## 7. Datenmodell (Entwurf)

### 7.1 Meldung (Event)
| Feld | Beschreibung |
|------|--------------|
| `ip` | Klartext-IPv4 (Einzeladresse) / IPv6 **präfix-normalisiert** (Default `/64`, konfigurierbar — Einzel-`/128` korroboriert nie). Hashing verworfen (§9). |
| `scenario` | Abstraktes Angriffs-**Szenario** aus dem Reason-Code-Katalog (z. B. `ssh-brute-force`, `smtp-auth-bruteforce`). **Join-Key**: Scoring ↔ SBOM/Profil ↔ Regeln ↔ STIX `attack-pattern`. **Keine konkreten Ports.** |
| `timestamp` | Zeitpunkt der Beobachtung |
| `port_class` *(optional, deprecated)* | Grobe Portklasse; entfällt zugunsten von `scenario`, um keine Dienst-Details zu leaken |
| `reporter_id` | Pseudonyme Knoten-ID (kryptografischer Schlüssel) |
| `signature` | Signatur des Melders |
| `subnet_id` | Herkunfts-Teilnetz/Trust-Domäne (für Föderation, §5) |
| `origin_trace` | Herkunfts-Kette (gegen Föderations-Rückkopplung, §5.2) |

### 7.2 Aggregierter Reputations-Eintrag pro IP
| Feld | Beschreibung |
|------|--------------|
| `ip` | Adresse |
| `score` | Aktueller normalisierter Reputations-Score (pro Trust-Domäne!) |
| `corroboration` | Anzahl + Diversität unabhängiger Melder |
| `first_seen` / `last_seen` | Für Decay |
| `reasons[]` | Aggregierte Angriffsgründe |
| `disputes` | Whitelist-/Anti-Trust-Votes |

### 7.3 Trust-Anchor-Eintrag
| Feld | Beschreibung |
|------|--------------|
| `key_id` | Öffentlicher Schlüssel des Anchors |
| `label` | Bezeichnung/Herkunft (z. B. „Mailcow-Projekt", „Spamtrap-Cluster-DE") |
| `weight` | Lokales Vertrauensgewicht |
| `valid_until` | Gültigkeit (für Rotation/Revocation) |
| `source` | `project-default` \| `self-added` \| `subnet` |

### 7.4 Whitelist-Eintrag
| Feld | Beschreibung |
|------|--------------|
| `ip_or_range` | Adresse/CIDR |
| `scope` | `local-only` (nie geteilt) \| `shared-vote` (trust-gewichtet) |
| `source` | `install-script` \| `manual` \| `federation` |

### 7.5 Evidenz-Aggregat (föderierter Import-Typ)
Was zwischen Teilnetzen geteilt und **lokal neu verrechnet** wird (Option b, §5.2).
Leichter als Roh-Events, reicher als ein opaker Score.

| Feld | Beschreibung |
|------|--------------|
| `ip` | Quelle (IPv4 einzeln / IPv6 präfix-normalisiert) |
| `scenario` | Angriffs-Szenario (§7.1) |
| `window` | Zeitfenster (für Decay + Korroborations-Frische) |
| `diversity_buckets` | **Pseudonymisierte** Zähler distinkter *unabhängiger* Melder je Bucket (ASN / Region / Subnetz; aus `origin_trace`/`subnet_id`) — **nie Melder-Identität**. Trägt §4.2 über den Import. |
| `evidence_weight` | Quell-/Subnetz-Gewicht (ehem. Trust-Discount) |

> On-Demand abrufen (DNSBL-Stil) für IPs, die dich real kontaktieren — Roh-Events
> bleiben optional (Observability-Plane). Reconciliation mit §11.

### 7.6 System-Profil (lokal, nie föderiert)
Treibt die Applicability-Gewichtung (§4.5) und die Regel-Auswahl.

| Feld | Beschreibung |
|------|--------------|
| `roles[]` | Wofür das System da ist (`mail`, `web`, `ssh`, …) — deklariert |
| `sbom_derived` | Ob/inwiefern aus lokaler SBOM verfeinert (semi-automatischer Matchmaker) |
| `applicable_scenarios[]` | Szenarien, die für dieses System relevant sind |

> **Invariante:** Profil **und** SBOM bleiben **strikt lokal** (eine SBOM ist die
> Karte der eigenen Angriffsfläche) — gleiche Familie wie die `local-only`-Whitelist.

---

## 8. Score-Dynamik

- **Eskalation:** Mehrfach-Angriffe / breitere Korroboration → Score steigt
  (überlinear bei hoher Quellen-Diversität).
- **Lokale Neuberechnung aus Evidenz (Kernmechanik).** Der Score ist **kein**
  importierter Fremdwert: jeder Knoten verrechnet **eigene + importierte Evidenz-
  Aggregate** (§7.5) über die **Regel-Engine** zu einem eigenen Score. Die Regeln
  sind operator-anpassbar (über den Defaults), Remote-Input bleibt beratend (§2 #8).
- **Effektives Gewicht** `= Korroboration (diversitätsgewichtet) × Evidenz-Gewicht
  (Quelle) × lokale Applicability (Profil, §4.5)`.
- **Decay (Degeneration):** Ohne neue Meldungen sinkt der Score über die Zeit gegen 0.
  - Funktioniert zugleich als **DSGVO-Löschfrist** (s. §9).
  - Halbwertszeit ist ein **kritischer Tuning-Parameter**:
    - zu kurz → Liste nutzlos
    - zu lang → bestraft unschuldige IP-Nachfolger (DHCP/CGNAT)
  - **Offen:** konkrete Halbwertszeit, ggf. abhängig vom Angriffstyp.

---

## 9. DSGVO / Rechtliches

**Korrektes Framing (entscheidend für Projekt-Vertrauen):**
Nicht „IP ist keine PII" — das hält rechtlich nicht. Sondern:

> **„IP = personenbezogenes Datum, verarbeitet auf Basis berechtigten Interesses an
> Netz-/Informationssicherheit (Art. 6(1)(f), ErwG 49), mit eingebauter Löschung via
> Decay (Art. 17) und lokaler Verantwortlichkeit."**

**Begründung / gegen die ursprüngliche Annahme:**
- **EuGH *Breyer* (C-582/14):** Auch dynamische IPs sind personenbezogen, sobald über
  Dritte (ISP) rechtlich identifizierbar. Das Projekt liefert *mehr* Kontext
  (IP + Zeit + Verhalten), nicht weniger → fest im personenbezogenen Bereich.
- **Art. 10 DSGVO:** Daten über (mutmaßliche) Straftaten genießen *erhöhten* Schutz,
  nicht weniger. Es sind **mutmaßliche** Angriffe → Falsch-Positive (CGNAT-Nachbarn,
  gekaperte Hosts, neu vergebene IPs) sind der eigentliche DSGVO-Kern.

**Hashing als Anonymisierung – verworfen:**
- IPv4-Raum (2³², ~4,3 Mrd.) ist trivial per Rainbow-Table umkehrbar → SHA-256(IP)
  ist **Pseudonymisierung, nicht Anonymisierung** (ErwG 26 → weiterhin PII).
- Hätte juristisch fast nichts gebracht, aber CIDR-Aggregation + Decay technisch
  zerstört. → **Klartext-IPs im Netz.**

**Eingebaute Compliance-Mechanismen:**
- Decay = automatische Löschung / Storage Limitation.
- Lokale Schwellen + Whitelist = Verantwortlicher ist der Admin, nicht das Netz.
- Berechtigtes Interesse Netzsicherheit = stärkste Rechtsgrundlage.

---

## 10. Pflicht-Schutzliste (Never-Block-Set)

**Sicherer Default, lokal tunebar, remote-immutabel.** Verhindert Selbst-Aussperrung
naiver Admins, ist aber **kein** harter Boden gegenüber dem Operator (Whitelists sind
tunebar, §2 #8) — die Unantastbarkeit gilt nur **gegenüber dem Netz**: kein Remote-
Signal kann das Set ändern. Empfohlene Default-Einträge:
- RFC1918 / private Ranges
- Root-DNS, öffentliche Resolver (z. B. 8.8.8.8, 1.1.1.1)
- Große Mail-Provider-Ranges (Google, Microsoft/Outlook)
- Cloudflare u. ä. CDN/Infra-Ranges

Wird je Föderation gepflegt (§6.2) und ist modellierbar als Spezialfall eines
Projekt-Trust-Anchors (§5.1). Lokal um die „lokale Wahrheit" ergänzt (Install-Script).

---

## 11. Skalierung, Performance & Datenflüsse

Zwei Skalierungsrisiken bei großen Netzen: (a) die Liste gemeldeter IPs wird zu groß,
um damit sinnvoll zu filtern; (b) Echtzeit-Gossip jedes Events erzeugt eine
Traffic-/CPU-Lawine. **Kernumkehr:** Die globale Liste wird **nicht lokal
materialisiert** („Torrent-Modell" verworfen) – stattdessen **Abfrage on-demand**
(DNSBL-Prinzip) + kompakter lokaler Vorfilter. Das löst beide Probleme zugleich.

### 11.1 Größenordnung (Realitätscheck)
- Aktiv bösartige IPs weltweit: **einstelliger Millionenbereich** zu jedem Zeitpunkt
  (vgl. CrowdSec ~1–3 Mio., Spamhaus), **nicht** der 4,3-Mrd.-IPv4-Raum.
- Ständig rotierend → Decay (§8) begrenzt die DB nach oben (Garbage Collector).

### 11.2 Drei-Ebenen-Architektur (Entkopplung)
| Ebene | Inhalt | Eigenschaft |
|-------|--------|-------------|
| **Data Plane** (Enforcement) | nur IPs über lokalem Threshold, die dich real kontaktieren | schlank, O(1)-Lookup |
| **Control Plane** (Reputation) | Score-DB / -Sync | eventual consistency, gebatcht, niedrige Prio |
| **Observability Plane** (Firehose) | Echtzeit-Eventstream für Angriffswellen-Monitoring | **Opt-in, default AUS** |

Der normale Admin belastet nur Data + Control Plane; der Live-Feed ist für
SOC/Forschung optional zuschaltbar (Beobachtung von Angriffswellen).

### 11.3 Listengröße beherrschen
- **DB ≠ Enforcement-Set:** Die schwere Reputations-DB ist nicht das, was die Firewall
  sieht. Der **lokale Threshold ist der natürliche Filter** – du konsumierst einen
  Score, importierst keine globale Liste. Aktives Set = Tausende, nicht Millionen.
- **Enforcement-Backend ist der eigentliche Engpass (Footgun):**
  - **Falsch:** eine `iptables`-Regel pro IP (Fail2Ban-Stil) → **O(n) pro Paket**,
    schmilzt bei Zehntausenden Einträgen.
  - **Richtig:** `ipset`/`nftables`-Hash-Sets → **O(1)**, tragen Hunderttausende+.
- **Bloom-Filter als Vorfilter:** 1 Mio. IPs @ 1 % FP ≈ ~1,2 MB. Der häufige Fall
  („IP unverdächtig?") wird lokal in µs mit „nein" beantwortet; nur Treffer brauchen
  einen echten Lookup.
- **CIDR-Aggregation (optional):** Wiederholungstäter-Subnetze zu Ranges verdichten →
  weniger Einträge. **Trade-off:** Kollateralschaden an Nachbarn (Spannung mit
  Problem D, IP ≠ Identität).

### 11.4 Traffic beherrschen
- **On-Demand-Abfrage (DNSBL-Modell):** Reputation per DHT-Lookup nur abfragen, wenn
  eine IP dich tatsächlich kontaktiert + lokaler TTL-Cache. Du fragst nur, was dich
  betrifft → kein Dauer-Traffic.
- **Aggregation am Rand:** keine 500 Einzel-Events gossipen, sondern periodische
  Summaries („IP X: 500 Auth-Versuche/5 Min"). Granularität gegen Bandbreite getauscht.
- **Relay-Hierarchie statt Full-Mesh:** Vollvermaschung ist O(N²). Aggregator-/Relay-
  Knoten je Föderation konsolidieren und verteilen (vgl. Tor Directory Authorities /
  Mastodon-Relays) – die **Föderation ist die natürliche Aggregationsgrenze**.
- **Signaturverifikation:** pro-Event-Verifikation ist CPU-teuer im großen Netz →
  Batch-Verifikation / Verifikation aggregierter Digests statt jedes Einzelevents.

### 11.5 Gutes-Nachbar-Prinzip (Nutzerperspektive)
> **Der Schutzmechanismus darf niemals selbst das Performance-Problem werden.**
- **Ressourcen-Budget:** konfigurierbares CPU-/Bandbreiten-Limit, niedrige Priorität
  (`nice`/cgroups).
- **Graceful degradation / Lastabwurf:** steht die Box selbst unter Angriffswelle,
  stellt der Daemon Fremd-Verifikation/Gossip zurück, schützt nur lokal und
  synchronisiert später nach (lokaler Schutz hat Vorrang vor Netz-Beitrag).
- **Sync-Modus wählbar:** Push (Full-Sync, kleine Föderationen) ↔ Pull-on-demand
  (große Netze) ↔ Hybrid.

---

## 12. Offene Probleme & Risiken

| # | Problem | Status |
|---|---------|--------|
| A | **Poisoning** grundsätzlich nie „gelöst", nur teuer/auffällig gemacht | mitigiert via §4 |
| B | **Bootstrapping/Henne-Ei** neuer Low-Trust-Knoten | gelöst via Ground-Truth-Genesis (§4.1) |
| C | **Verifizierbarkeit** einzelner Meldungen (High-Trust-Knoten gehackt) | mitigiert via Korroboration + schnellem Trust-Decay |
| D | **IP ≠ Identität** (CGNAT, DHCP) → Decay-Tuning | offen (Halbwertszeit, §8) |
| E | **Privacy des Melders** (leakt Infra-Topologie, Whitelist-Präferenzen) | teils gelöst via Lokal-only-Whitelist (§6.2); Tor-artige Einreichung vs. Sybil-Accountability **offen** |
| F | **Pflege Never-Block-Set + lokale Wahrheit** | adressiert via §6.2 (Install-Script); Governance offen |
| G | **Ground-Truth-Verifikation** im dezentralen Modell B | offen |
| H | **Massen-Whitelist-Angriff** zum Schutz echter Angreifer | mitigiert via gewichtete Whitelist-Votes (§4.4) |
| I | **Re-Zentralisierung** durch flächige Übernahme von Projekt-Anchors | mitigiert via lokal entfernbarer Anchors (§5.1), Default ≠ Zwang |
| J | **Schlüssel-Management** (Rotation, Revocation, kompromittierte Keys) | adressiert via §6.3; Detail-Format offen |
| K | **Föderations-Rückkopplung & Fragmentierung** (Mehrfachzählung A↔B; verdünnter Netzwerkeffekt) | mitigiert via Herkunfts-Tracking/Hop-Discount (§5.2) |
| L | **Bösartiges/kompromittiertes Teilnetz** | mitigiert via Defederation (§5.2) |
| M | **Echtsystem als Ground Truth** → Verlust der Null-False-Positive-Eigenschaft | mitigiert via Honeypot-Semantik im Echtsystem / Spamtraps (§6.1) |
| N | **Zu breite Auto-Whitelist** durch Install-Script | mitigiert via konservativer Erkennung (§6.2) |
| O | **Listengröße** sprengt Filter | mitigiert via DB≠Enforcement-Set, Threshold-Filter, Bloom, Decay (§11.3) |
| P | **Traffic-Lawine** im großen Netz (Echtzeit-Gossip) | mitigiert via On-Demand/DNSBL, Aggregation, Relay-Hierarchie (§11.4) |
| Q | **Enforcement-Backend O(n)** (Fail2Ban-Stil) schmilzt | gelöst via ipset/nftables O(1) (§11.3) |
| R | **CPU-Last durch Signaturverifikation** im großen Netz | mitigiert via Batch-Verifikation + Lastabwurf (§11.4/§11.5) |
| S | **Sybil via Discovery** – viele DHT-Phantome fluten den Stranger-Pool | mitigiert via bestehendem `strangerCap` pro IP (§4.2/§4.3) |
| T | **Privacy des Advertisers** – DHT-Eintrag leakt IP + Peer-ID | mitigiert via `advertise: false` Opt-out (§14.1/§14.5); Onboarding-Pflicht |
| U | **Quell-Reputation als Meta-Poisoning** (eine *gute* Föderation als „Vergifter" markieren) | mitigiert: dieselben strukturellen Abwehren wie IP-Signale + bleibt **beratend**, nie erzwungener globaler Ban (Future-Feature, §13) |
| V | **IPv6 `/128`-Reputation nutzlos** (Angreifer besitzt 2^64 Adressen pro `/64`) | gelöst via **Präfix-Normalisierung** (`/64` Default, §7.1) |
| W | **Regel-Fehlkonfiguration** senkt lokale Schutzwirkung | mitigiert via **sichere Defaults** + Remote-advisory-Invariante (§2 #8); Schutzregeln in der UI markiert |
| X | **Evidenz-Import-Volumen** (Option b) bedroht §11-Schlankheit | mitigiert via **On-Demand-Evidenz-Aggregate** (§7.5) statt Roh-Events/opaker Scores |

---

## 14. Föderations-Entdeckung (Federation Discovery)

Das Schwarm ist nur wirksam ab einer kritischen Masse. Das manuelle Invite/Join-Protokoll
(§5.2) erzeugt hochvertrauenswürdige Föderationen, aber auch Bootstrapping-Reibung:
Ein Knoten ohne bestehende Kontakte nimmt nicht am Netz teil. Discovery löst das, indem
Knoten sich gegenseitig automatisch finden – **ohne eine vorhandene Vertrauensbeziehung
vorauszusetzen** und ohne das Trust-Modell zu umgehen.

### 14.1 Zwei Opt-out-Flags (beide Default: **an**)

| Flag | Funktion |
|------|----------|
| `discovery.advertise` | Veröffentlicht diesen Knoten am DHT-Rendezvous-Punkt |
| `discovery.discover` | Sucht aktiv im DHT nach weiteren Peers |

Beide unabhängig konfigurierbar (lokale Souveränität, Leitprinzip 7). Betreiber,
die vollständige Privatheit wollen (z. B. firmeneigene Netze), setzen `advertise: false`
und verlassen sich auf manuelles Invite/Join.

### 14.2 Entdeckungsmechanismus

**Primär – DHT-Rendezvous (dezentral):**
Knoten melden sich unter einem festen Schlüssel (`/federloom/v1/peers`) im bestehenden
Kademlia-DHT an. Kein Projekt-Server nötig; nutzt die bereits aufgebaute Transport-Schicht.

**Fallback – Signierte Relay-Liste (Kalt-Start):**
Eine vom Projekt signierte, versionierte JSON-Datei mit bekannten Bootstrap-/Relay-Knoten
(analog zu Tor-Directory-Authorities). Wird mit dem Release ausgeliefert, ist lokal
überschreibbar. Wird nur verwendet, wenn der DHT noch nicht erreichbar ist (Erstinstallation,
keine Peers vorhanden).

Die Relay-Liste folgt dem Anchor-Prinzip (§5.1): projekt-signiert als sinnvoller **Default,
kein Zwang**. Betreiber können eigene Bootstrap-Listen eintragen und die Projektliste
entfernen.

### 14.3 Trust neu entdeckter Knoten

Neu entdeckte (nicht eingeladene) Knoten erhalten `trust.stranger_weight` – denselben
Wert wie jeder nicht verankerte Melder. Das bestehende `strangerCap` pro IP begrenzt
den koordinierten Sybil-Beitrag vieler entdeckter Fremder (Problem S, §12).

Um einen entdeckten Knoten hochzustufen: `federloomctl trust import` (manuelles Verbürgen).
Das Trust-Modell bleibt unverändert; Discovery erweitert nur den Pool erreichbarer Knoten.

### 14.4 Zusammenspiel mit Föderations-Modus

Der bestehende `federation.mode` (allowlist / blocklist, §5.2) gilt unverändert.
Discovery liefert mehr Fremde in den Pool; ihr Gewicht ist durch die Stranger-Mechanik
gedeckelt. Ein `allowlist`-Knoten verbindet sich mit entdeckten Peers, gewichtet deren
Meldungen aber nur mit `stranger_weight`.

### 14.5 Datenschutz-Hinweis

`advertise: true` veröffentlicht die IP-Adresse und Peer-ID dieses Knotens im DHT –
**öffentlich sichtbar für jeden DHT-Teilnehmer**. Betreiber in datenschutzsensiblen
Umgebungen sollen `advertise: false` setzen. Die Onboarding-Dokumentation muss dies
prominent erklären.

---

## 12a. Implementation Traceability (2026-07)

Honest status of each design area in the current codebase. This table — not the
§13 "Nächste Schritte" list — is the source of truth for what is live.
`DONE` = implemented and tested · `PARTIAL` = present but incomplete/inert ·
`PLANNED` = designed, not yet built (remediation sub-project in parentheses).

| Spec § | Area | Package | Status |
|---|---|---|---|
| §4.1 | Ground-truth anchors | `internal/trust`, honeypot/spamtrap ingest | DONE |
| §4.2 | Diversity-weighted corroboration (ASN/geo) | — | PLANNED (D) |
| §4.3 | Asymmetric decay | `internal/reputation` | DONE |
| §4.4 | Dispute / anti-trust votes | — | PLANNED (E) |
| §4.5 | Applicability weighting | — | PLANNED (E) |
| §5.1 | Trust anchors (Person keys, peer certs) | `internal/trust`, `internal/identity` | DONE |
| §5.2 | Federation import / discount / origin-trace | `internal/node`, `internal/transport`, `internal/trust` | PARTIAL — subnet-bridge forwarding makes origin-trace + per-hop discount active (E1); evidence-aggregate import PLANNED (E2) |
| §7.1 | Event model | `pkg/proto` | DONE — `port_class` deprecated-retained |
| §7.1 | IPv6 `/64` prefix normalization | `internal/netutil`, `internal/node`, `internal/enforce` | DONE |
| §7.2 | ScoreEntry aggregate | `pkg/proto`, `internal/repquery` | DONE — exchanged as the on-demand query answer (E3) |
| §7.5 | EvidenceAggregate (federated import type) | — | PLANNED (E) |
| §7.6 | System profile / SBOM | — | PLANNED (E) |
| §8 | Score dynamics (logistic accumulation, decay) | `internal/reputation`, `internal/rules` | DONE |
| §9 | GDPR framing (cleartext IP, decay = deletion) | `internal/store` (TTL) | DONE |
| §10 | Never-block set | `internal/enforce` | DONE — incl. public resolvers |
| §11.3 | O(1) enforcement (ipset/nftables) | `internal/enforce` | DONE |
| §11.4 | On-demand query / pull transport | `internal/repquery` | PARTIAL — read path via configured aggregators (E3); DHT/bloom + materialise-on-verdict PLANNED |
| §14 | Federation discovery (DHT + relay list) | `internal/discovery` | DONE |

## 13. Nächste Schritte

> **Superseded (2026-07-10):** Die Sequenzierung liegt jetzt in
> [docs/roadmap.md](roadmap.md); der Live-Status in §12a. Diese Liste bleibt
> als historischer Design-Kontext erhalten — mehrere Punkte (u. a. 5, 8, 10,
> 11, 15) sind inzwischen umgesetzt.

1. **Decay-Halbwertszeit** modellieren (ggf. pro Angriffstyp) – Problem D.
2. **Melder-Privacy** entscheiden (Anonymität ↔ Accountability) – Problem E.
3. **Ground-Truth-Betriebsmodell** wählen (Honeypot vs. Echtsystem+Spamtrap; A/B) – §4.1/§6.1.
4. **Score-Normalisierung & Schwellwert-Defaults** für Mailcow festlegen.
5. **Transport/Gossip-Protokoll** spezifizieren (DHT vs. Gossip vs. hybrid).
6. **Föderations-Semantik:** Trust-Discount-Funktion, Herkunfts-Tracking,
   Allowlist- vs. Blocklist-Default, Defederation – Probleme K/L.
7. **Anchor-Schlüssel-Lebenszyklus** spezifizieren (Format, Rotation, Revocation) – Problem J.
8. **Install-Script** bauen: Auto-Detection lokaler Wahrheit → Lokal-only-Whitelist – §6.2.
9. **Repository-Onboarding-Doku** schreiben, die §6 prominent erklärt (Gründungspflichten
   jeder Föderation: Ground-Truth-Anker, Whitelist-Pflege, Schlüssel-Management, Override-Prinzip).
10. **Enforcement-Backend** festlegen: ipset/nftables (nicht iptables-Regel-pro-IP) – Problem Q.
11. **Sync-Modell** entscheiden: Push vs. Pull-on-demand (DNSBL) vs. Hybrid; Bloom-Vorfilter – §11.
12. **Ressourcen-Budget & Lastabwurf** spezifizieren (CPU/Bandbreite, graceful degradation) – §11.5.
13. **Observability-Plane** als Opt-in entwerfen (Angriffswellen-Monitoring, default aus) – §11.2.
14. Prototyp-Reihenfolge: Ground-Truth + Diversitäts-Korroboration zuerst (80 %),
    danach Trust-Anchors, zuletzt Teilnetz-Föderation.
15. **Föderations-Entdeckung** implementieren: DHT-Rendezvous + signierte Relay-Liste
    als Fallback; zwei Opt-out-Flags (`advertise`/`discover`, beide default an) – §14.
16. **System-Profil + Applicability** (§4.5/§7.6): Rollen + SBOM-Matchmaker,
    soft down-weighting beim Konsumieren.
17. **Evidenz-Import-Modell (Option b)**: `EvidenceAggregate` (§7.5), lokale
    Regel-Neuberechnung (§8), Diversity-Buckets, IPv6-Präfix.
18. **STIX/TAXII-Egress** über die bestehende REST-API (Poll) – §3.
19. **MISP-Ingest-Adapter** (`ingest.Source`) – **post-MVP**.
20. **Quell-Reputations-Schicht** als **Future-Feature**: „diese Föderation
    vergiftet" teilen (mappt auf MSC2313 `m.policy.rule.server`), beratend, strukturell
    abgesichert (Risiko U).
21. **Szenario-/Reason-Code-Katalog-Governance** + festes Mapping nach STIX
    `attack-pattern` (Szenario ist jetzt Lastträger über 5 Schichten).
22. **Key-Handling** gegen das Matrix-Signing-Key-Modell benchmarken (optional) –
    s. `docs/prior-art.md`.
23. **`docs/prior-art.md`** ins Repo aufnehmen (Positionierung + Honesty-Boundary).
