# Labeled Threat Intelligence Dataset Methodology
### Emotet + Qakbot Infection Chain (PCAP Derived IOC Dataset)

**Author:** Hadiya Zuberi
**Source material:** Network traffic capture (`2018-12-14-Emotet-infection-with-Qakbot.pcap`), originally sourced from netresec.com, analyzed via Wireshark
**Purpose:** Demonstrate a structured, ML-ready approach to labeling threat intelligence indicators, with explicit confidence levels, evidence traceability, and MITRE ATT&CK mapping.


## 1. Why this format

Raw incident reports are written for human readers. Machine learning systems and detection engines need something different: consistently structured records where every field has a fixed definition, every label is traceable to specific evidence, and uncertainty is explicitly marked rather than implied. This dataset reformats a real incident analysis into that structure.

## 2. Schema

| Field | Definition | Allowed values |
|---|---|---|
| `event_id` | Unique identifier for this labeled record | string |
| `source_pcap` | Origin capture file, for traceability | filename |
| `timestamp` | Time of observed event, where available | ISO 8601 or "capture-relative" if absolute time unavailable |
| `src_ip` / `dst_ip` | Observed network endpoints | IP address |
| `indicator_type` | Category of evidence | `domain`, `ip`, `file_hash`, `file_name`, `http_artifact`, `dns_query`, `tls_event` |
| `indicator_value` | The actual observed value | string |
| `label` | Classification of this indicator | `malicious`, `benign`, `suspicious_unconfirmed` |
| `confidence` | Strength of evidence behind the label | `confirmed` (direct behavioral/payload evidence), `likely` (strong correlated signal), `low` (single weak signal, needs further correlation) |
| `mitre_technique_id` | Mapped MITRE ATT&CK technique, if applicable | e.g. `T1566.001`, `T1105`, or `n/a` |
| `evidence_note` | Short justification tied to the specific observation that produced this label | free text, one line |

## 3. Labeling rules (decided in advance, applied consistently)

- A label of `malicious` requires direct evidence of malicious behavior (payload delivery, confirmed C2 traffic pattern, known-bad hash/domain) — not just presence in the same session as other malicious traffic.
- A label of `suspicious_unconfirmed` is used when a signal is anomalous but not independently confirmed as malicious e.g., a single TLS handshake to a repeatedly-contacted host, without payload or DNS corroboration.
- Standard protocol behavior (e.g., reverse-DNS `.arpa` lookups, ordinary TLS Client Hello negotiation) is labeled `benign` by default and only escalated with corroborating evidence this prevents inflating false-positive rates in the training data.
- Every non-benign label must have an `evidence_note` referencing the specific packet-level or session-level observation that justifies it.

## 4. Corrections made from the original incident report

The original human-readable incident report (Jira-based investigation, April 2026) contained two labeling decisions that this dataset corrects, documented here for transparency and QA purposes:

1. **`.arpa` reverse DNS queries** were originally flagged as a "suspicious domain." Reverse-DNS (PTR) lookups are standard, ubiquitous network behavior and are not inherently suspicious. Relabeled as `benign` in this dataset.
2. **TLS Client Hello traffic** to a repeatedly-contacted host was originally described as "C2 discovery." A Client Hello alone only indicates the start of a TLS session it is not, by itself, evidence of command-and-control. Relabeled as `suspicious_unconfirmed` / `low` confidence, pending further correlation (e.g., JA3 fingerprinting or destination reputation, not performed in the original lab).
3. **Host IP inconsistency**: the original report referenced three source IPs (73.233.236.181, 72.233.236.161, and a third variant) for what context indicates is very likely a single external host. This dataset uses 73.233.236.181 as the canonical value, consistent with the earliest and most-repeated reference in the source material, and flags this as an assumption for future verification against the raw pcap rather than silently resolving it.

## 5. Coverage note

This dataset currently reflects a single incident (Emotet dropper → Qakbot banking trojan chain) and is intended as a schema demonstration, not a production-scale training set. A production version would need: (a) many more incidents for statistical coverage, (b) an explicit benign-traffic baseline sampled from non-incident capture windows, and (c) inter-annotator agreement scoring once more than one labeler is involved.

## 6. Files in this dataset

- `methodology.md` this document
- `labeled_dataset.csv` the structured IOC/indicator records described above
