# SOC Analyst Learning Repository

A structured learning and revision repository covering Security Operations Center (SOC) fundamentals, SIEM, log analysis, Splunk, threat detection, incident investigation, and related blue-team skills.

## Learning roadmap

Follow the modules in order. Each module has its own folder and README containing the detailed study notes.

| Day | Module | Topics |
|---|---|---|
| [Day 01](01-SIEM-Fundamentals/README.md) | SIEM Fundamentals | SIEM concepts, architecture, data pipeline, logs, detection, alert triage, threat hunting, Splunk examples, interview preparation |
| [Day 02](02-Log-Analysis/README.md) | Log Analysis | Windows and Linux logs, event IDs, authentication analysis, investigation context |
| [Day 03](03-Log-Collection-Parsing-Normalization/README.md) | Log Collection, Parsing & Normalization | Collection methods, parsing, normalization, enrichment, data quality |
| [Day 04](04-Splunk-Architecture-Data-Ingestion/README.md) | Splunk Architecture & Data Ingestion | Splunk components, data flow, forwarders, configuration, ingestion troubleshooting |
| [Day 05](05-Splunk-SPL-Fundamentals/README.md) | Splunk SPL Fundamentals | Search pipeline, fields, filtering, aggregation, time-based searches, SOC queries |
| [Day 06](06-Advanced-SPL-for-SOC-Analysts/README.md) | Advanced SPL | Regex, JSON, lookups, eventstats, streamstats, transactions, joins, correlation |
| [Day 07](07-Threat-Detection-Engineering/README.md) | Threat Detection Engineering | Detection lifecycle, IOC/IOA/TTP, thresholds, correlation, MITRE ATT&CK, rule quality |
| [Day 08](08-Incident-Investigation-and-Response/README.md) | Incident Investigation & Response | Alert triage, investigation workflow, containment, eradication, recovery, evidence, incident reports |

## How to use this repository

1. Start with Day 01 and continue in sequence.
2. Read each module's concepts and examples.
3. Reproduce command-line and SPL examples in an authorised lab environment.
4. Verify field names, indexes, sourcetypes, and data schemas before adapting searches to your own Splunk instance.
5. Use the interview questions and revision sections to check your understanding.

## Important notes

- These materials are educational study notes, not operational instructions for responding to a live incident.
- Only investigate systems and data that you are authorised to access.
- Follow your organisation's approval, evidence-handling, and incident-response procedures.
- SIEM and security-product behaviour varies by version and configuration. Validate examples against official documentation and your environment.
- An alert is not proof of compromise. Validate evidence and distinguish observed facts from assumptions.

## Repository structure

```text
Soc/
├── README.md
├── 01-SIEM-Fundamentals/
│   └── README.md
├── 02-Log-Analysis/
│   └── README.md
├── 03-Log-Collection-Parsing-Normalization/
│   └── README.md
├── 04-Splunk-Architecture-Data-Ingestion/
│   └── README.md
├── 05-Splunk-SPL-Fundamentals/
│   └── README.md
├── 06-Advanced-SPL-for-SOC-Analysts/
│   └── README.md
├── 07-Threat-Detection-Engineering/
│   └── README.md
└── 08-Incident-Investigation-and-Response/
    └── README.md
```

---

**Progress:** 8 learning modules documented.

*Maintained as a practical reference for SOC learning, revision, and entry-level analyst interview preparation.*
