# SIEM — Complete Study & Interview Reference

> **Purpose:** A structured, practical reference for learning Security Information and Event Management (SIEM) from fundamentals to advanced SOC operations. Written for study, revision, hands-on labs, and SOC Analyst interviews.
>
> **Learning target:** Build the knowledge expected of an entry-level SOC Analyst and develop a foundation for Tier 2 investigation and detection engineering.
>
> **Important:** SIEM products differ. Examples below use Splunk terminology where useful; always verify field names, data models, parsing rules, and product-specific behaviour in your own environment.

---

## Table of Contents

1. [SIEM Fundamentals](#1-siem-fundamentals)
2. [Why Organizations Use SIEM](#2-why-organizations-use-siem)
3. [Core Terminology](#3-core-terminology)
4. [SIEM Architecture and Data Pipeline](#4-siem-architecture-and-data-pipeline)
5. [Logs and Security Telemetry](#5-logs-and-security-telemetry)
6. [Collection, Parsing, Normalization, and Enrichment](#6-collection-parsing-normalization-and-enrichment)
7. [Storage, Indexing, and Search](#7-storage-indexing-and-search)
8. [Detection Engineering](#8-detection-engineering)
9. [Event Correlation and Investigation Context](#9-event-correlation-and-investigation-context)
10. [Alert Triage and Incident Handling](#10-alert-triage-and-incident-handling)
11. [Threat Intelligence and MITRE ATT&CK](#11-threat-intelligence-and-mitre-attck)
12. [Threat Hunting](#12-threat-hunting)
13. [Advanced SIEM Capabilities](#13-advanced-siem-capabilities)
14. [SIEM, EDR, XDR, IDS/IPS, and SOAR](#14-siem-edr-xdr-idsips-and-soar)
15. [SIEM Deployment and Operations](#15-siem-deployment-and-operations)
16. [SIEM Metrics and Detection Quality](#16-siem-metrics-and-detection-quality)
17. [Investigation and Evidence Handling](#17-investigation-and-evidence-handling)
18. [Practical Splunk Examples](#18-practical-splunk-examples)
19. [Common SIEM Use Cases](#19-common-siem-use-cases)
20. [Limitations and Common Challenges](#20-limitations-and-common-challenges)
21. [SOC Analyst Interview Questions](#21-soc-analyst-interview-questions)
22. [Glossary](#22-glossary)
23. [Study and Practical Checklist](#23-study-and-practical-checklist)
24. [Further Learning](#24-further-learning)

---

## 1. SIEM Fundamentals

### 1.1 What is SIEM?

**SIEM (Security Information and Event Management)** is a technology and operational capability that collects security-relevant telemetry from multiple sources, makes that data searchable and useful, applies analytics and detection logic, and helps security teams identify, investigate, and respond to potential threats.

A SIEM brings security data from systems such as:

- Windows and Linux endpoints and servers
- Identity providers and Active Directory
- Firewalls, routers, VPN gateways, and network devices
- IDS/IPS platforms
- Endpoint Detection and Response (EDR) products
- DNS, DHCP, proxy, web, email, and application services
- Cloud platforms and SaaS applications
- Databases and critical business applications

The SIEM provides a centralized view of activity across an organization's environment. It does not automatically prove that an attack occurred. It provides data and detections that analysts must validate in context.

### 1.2 Security Information Management vs Security Event Management

Historically, the terms described related capabilities:

- **Security Information Management (SIM):** Long-term collection, storage, reporting, and analysis of security log information.
- **Security Event Management (SEM):** Real-time monitoring, event analysis, correlation, and alerting.
- **SIEM:** Combines information management and event management capabilities.

Modern products often combine these with threat intelligence, analytics, automation, and investigation workflows.

### 1.3 Why is SIEM important?

A medium or large organization may generate millions of events every day. Manually opening logs on every endpoint, server, firewall, and cloud service is inefficient and makes cross-system investigations difficult.

A SIEM helps teams:

1. Centralize security telemetry.
2. Search current and historical events.
3. Detect suspicious patterns and policy violations.
4. Correlate events from different systems.
5. Enrich events with identity, asset, and threat context.
6. Prioritize and assign alerts.
7. Support incident response and investigations.
8. Retain records for audit, compliance, and investigation requirements.

### 1.4 What a SIEM does not do

A SIEM is not automatically:

- An antivirus or EDR agent.
- A firewall that blocks all malicious traffic.
- A guarantee that every attack will be detected.
- A replacement for skilled analysts.
- A complete digital-forensics suite.
- A source of truth when its data sources are incomplete or inaccurate.

Some SIEM platforms can initiate response actions through integrations or SOAR workflows, but those actions depend on configuration, permissions, approvals, and connected products.

---

## 2. Why Organizations Use SIEM

Consider a company with employee laptops, domain controllers, Linux servers, cloud workloads, firewalls, VPN access, and email services.

An attacker may:

1. Guess or steal an employee password.
2. Sign in through a VPN.
3. Access a server.
4. Execute a suspicious script.
5. Create persistence.
6. Access sensitive files.
7. Attempt to move to another system.

Each system may record only part of the activity. The SIEM helps analysts bring the evidence together into a timeline.

### Business and security benefits

- **Visibility:** A consolidated view of activity across systems.
- **Detection:** Identification of known malicious patterns and suspicious behaviour.
- **Investigation:** Searchable evidence across multiple sources.
- **Response coordination:** Alerts, cases, ownership, and escalation workflows.
- **Compliance support:** Retention, reporting, and audit evidence, subject to applicable requirements.
- **Threat hunting:** Proactive searches for activity that existing alerts may not have identified.

---

## 3. Core Terminology

These terms are foundational for SOC work and interviews.

| Term | Meaning |
|---|---|
| Log | A recorded message or record generated by a system or application. |
| Event | An occurrence recorded by a system, such as a login or process creation. |
| Telemetry | Observable data about system, user, application, or network activity. |
| Alert | A notification created when detection logic or an analytic identifies activity of interest. |
| Incident | A confirmed or suspected security event or set of related events requiring coordinated investigation or response. |
| IOC | Indicator of Compromise, such as a malicious IP, domain, file hash, or URL. |
| IOA | Indicator of Attack, describing behaviour associated with an attack. |
| TTP | Tactics, Techniques, and Procedures used by threat actors. |
| Correlation | Connecting related events using shared attributes, time, sequence, or context. |
| Parsing | Extracting structured fields from raw event data. |
| Normalization | Mapping data into a consistent schema and field structure. |
| Enrichment | Adding context such as asset owner, geolocation, threat intelligence, or identity details. |
| Detection rule | Logic that identifies activity meeting specified conditions. |
| Use case | A defined security monitoring objective and its detection/investigation logic. |
| False positive | Benign activity incorrectly identified as suspicious or malicious. |
| False negative | Malicious activity that a detection fails to identify. |
| Baseline | A model or description of normal activity for a system, user, or environment. |
| Triage | Initial assessment to determine an alert's validity, priority, and next steps. |
| Escalation | Passing an alert or incident to a more appropriate team or higher response tier. |
| Case management | Recording findings, evidence, ownership, status, and actions for an investigation. |

### Event vs Alert vs Incident

Example:

- **Event:** A user enters an incorrect password.
- **Alert:** A rule detects 30 failed logins against an account within five minutes.
- **Incident:** Investigation finds that the activity was unauthorized and the account was accessed by an attacker.

An alert is not automatically an incident. Analysts validate the alert using evidence, context, and organizational procedures.

---

## 4. SIEM Architecture and Data Pipeline

A typical SIEM data flow is:

```text
Data Sources
    |
    v
Collection / Ingestion
    |
    v
Parsing and Field Extraction
    |
    v
Normalization and Enrichment
    |
    v
Storage and Indexing
    |
    v
Search, Analytics and Correlation
    |
    v
Detection / Alert Generation
    |
    v
SOC Triage and Investigation
    |
    v
Response, Escalation and Lessons Learned
```

### 4.1 Data sources

The quality of SIEM detection depends on the quality and coverage of its data sources.

Examples:

- Windows Security, System, and application logs
- Linux authentication and system logs
- Active Directory domain controller events
- Firewall allow/deny records
- DNS query and response logs
- Proxy and web gateway logs
- VPN authentication and session logs
- EDR process, file, network, and detection telemetry
- Cloud audit logs and identity sign-in records
- Email security events

### 4.2 Collection and ingestion

Collection is the process of moving telemetry from its source into the SIEM.

Common methods:

| Method | Description |
|---|---|
| Agent | Software on a host collects and forwards telemetry. |
| Forwarder | A lightweight component forwards selected data to a central platform. |
| Syslog | A widely used message format and transport ecosystem for device and application logs. |
| API | A platform retrieves or receives data through an application programming interface. |
| Cloud connector | A service integration collects audit and security events from cloud platforms. |
| Agentless collection | Data is collected without installing a dedicated endpoint agent, for example through APIs or remote protocols. |
| Network sensor | Observes network traffic or metadata and sends relevant telemetry. |

**Splunk example:** Splunk Universal Forwarder can monitor selected files or Windows event channels and forward data to a Splunk receiving endpoint. It is a data-forwarding component, not the SIEM's entire detection engine.

### 4.3 Parsing and field extraction

Raw logs often contain unstructured or semi-structured text. Parsing identifies meaningful values and exposes them as fields.

Raw Linux example:

```text
Failed password for invalid user test from 203.0.113.25 port 51514 ssh2
```

Possible extracted fields:

- action: failed authentication
- account: test
- source_ip: 203.0.113.25
- source_port: 51514
- protocol/service: SSH

Field names vary by parser and product. The example IP belongs to the documentation range and is not a real threat indicator.

### 4.4 Normalization

Different vendors describe similar activity using different field names and structures.

For example, one source may use `src_ip`, another `SourceAddress`, and another `client.ip`.

Normalization maps these to a consistent schema, such as:

- source.ip
- destination.ip
- user.name
- event.action
- event.category
- event.outcome
- host.name
- process.name

A common schema helps analysts write detections that work across different data sources. Examples of schemas include Elastic Common Schema (ECS) and the Splunk Common Information Model (CIM).

### 4.5 Enrichment

Enrichment adds useful context to an event.

Examples:

- Map an IP address to an internal asset or known external network.
- Add asset criticality and business owner.
- Resolve a username to a department or privilege level.
- Add threat-intelligence reputation for a domain or file hash.
- Identify whether a host is a domain controller or production server.
- Add geographic or autonomous-system context where appropriate.

Enrichment improves investigation quality, but enriched information must be checked for freshness and reliability.

### 4.6 Storage and indexing

The SIEM stores events so analysts can retrieve and analyze them. Design considerations include:

- Search performance
- Data volume and ingestion rate
- Retention requirements
- Storage cost
- Access control
- Data integrity
- Backup and disaster recovery
- Hot, warm, cold, or archive storage tiers where supported

### 4.7 Search and analytics

Analysts use search languages, dashboards, scheduled searches, correlation rules, and analytics to examine activity.

Examples include:

- Find failed logins for a user.
- Count authentication failures by source IP.
- Identify a successful login after repeated failures.
- Search for suspicious process execution.
- Correlate an endpoint alert with identity and network events.

### 4.8 Alerting and case management

A detection may generate an alert that is routed to an analyst or case-management system. A useful alert should include:

- Detection name and description
- Time range
- Affected user and asset
- Source and destination details
- Relevant raw events or evidence
- Severity and rationale
- ATT&CK mapping where applicable
- Suggested investigation steps
- Rule version and data source

---

## 5. Logs and Security Telemetry

### 5.1 Common log categories

| Category | Examples | Investigation value |
|---|---|---|
| Identity | Authentication, MFA, account changes | Account compromise, brute force, privilege abuse |
| Endpoint | Process, file, registry, service, EDR events | Malware, execution, persistence |
| Network | Firewall, IDS/IPS, flow, DNS | Scanning, command-and-control, exfiltration |
| Web | HTTP access, proxy, WAF | Web attacks, suspicious requests |
| Email | Delivery, URL click, attachment verdict | Phishing and malicious attachments |
| Cloud | Sign-ins, audit activity, API calls | Cloud account misuse and configuration changes |
| Application | Errors, access, administrative actions | Abuse of application functionality |
| Database | Queries, authentication, privilege changes | Unauthorized access and data misuse |

### 5.2 Windows logs

Windows Event Viewer organizes records into channels such as Security, System, and Application. Domain controllers and endpoints can produce security-relevant audit events.

Useful Windows Security Event IDs include:

| Event ID | Meaning | SOC relevance |
|---|---|---|
| 4624 | Successful logon | Investigate unusual or unexpected access |
| 4625 | Failed logon | Brute-force and password-spraying analysis |
| 4634 | Logoff | Session activity |
| 4648 | Logon using explicit credentials | Possible alternate credential use |
| 4672 | Special privileges assigned to new logon | Privileged logon context |
| 4688 | Process creation | Execution and command-line investigation when auditing is configured |
| 4697 | Service installed | Possible service-based persistence |
| 4720 | User account created | Unexpected account creation |
| 4722 | User account enabled | Unexpected account activation |
| 4724 | Attempt to reset an account password | Account administration investigation |
| 4728 | Member added to a security-enabled global group | Privilege/group membership change |
| 4732 | Member added to a security-enabled local group | Local group privilege change |
| 4729 | Member removed from a security-enabled global group | Group membership change |
| 4740 | User account locked out | Repeated authentication failures |
| 4768 | Kerberos authentication ticket requested (TGT) | Kerberos authentication analysis |
| 4769 | Kerberos service ticket requested | Service access and Kerberos investigation |
| 4771 | Kerberos pre-authentication failed | Authentication failure investigation |
| 4776 | Credential validation | NTLM authentication investigation |

**Important:** Event IDs alone do not prove malicious activity. Interpret the event with its fields, logon type, account, source, host, time, audit policy, and surrounding events. Some events require particular audit policy settings and may not be present by default.

### 5.3 Linux logs

Common locations vary by distribution and logging configuration.

- `/var/log/auth.log`: Common on Debian/Ubuntu systems for authentication-related messages.
- `/var/log/secure`: Common on some Red Hat-family systems.
- `/var/log/syslog`: General system messages on some Debian-family systems.
- `/var/log/messages`: General system messages on some distributions.
- `journalctl`: Queries the systemd journal.

Examples of useful Linux activity:

- SSH login success or failure
- sudo command execution
- User and group creation
- Service changes
- Scheduled task changes
- Unexpected listening services
- Authentication configuration changes

Useful commands:

```bash
# Review recent authentication messages (where auth.log exists)
sudo tail -n 100 /var/log/auth.log

# Search for SSH authentication failures
sudo grep -i "failed password" /var/log/auth.log

# Review systemd journal messages
sudo journalctl --since "1 hour ago"

# Review messages from the SSH service (service name may vary)
sudo journalctl -u ssh --since today
```

### 5.4 Network and security-device logs

Examples:

- Firewall: source, destination, ports, protocol, action, rule
- DNS: queried domain, client, response, timestamp
- Proxy: URL, user, action, category, response code
- VPN: account, source address, assigned address, connection time
- IDS/IPS: signature, source/destination, severity, action
- DHCP: lease assignment and client identity

Network logs are particularly useful when combined with endpoint and identity telemetry.

### 5.5 Time synchronization

Accurate timestamps are essential for correlation and incident timelines.

Check:

- Time zone consistency
- NTP synchronization
- Clock drift
- Event time versus ingestion time
- Timestamp parsing and daylight-saving behaviour

A log arriving late should not automatically be treated as an event that happened at ingestion time. Preserve and understand the original event timestamp.

---

## 6. Collection, Parsing, Normalization, and Enrichment

These concepts are related but not interchangeable.

| Stage | Main question | Example |
|---|---|---|
| Collection | How does data reach the SIEM? | Forwarder sends Windows events |
| Parsing | What values are in the raw event? | Extract username and source address |
| Normalization | How do we represent equivalent fields consistently? | Map different source IP fields to source.ip |
| Enrichment | What additional context helps interpret the event? | Add asset owner and threat reputation |
| Indexing | How can the data be stored and searched efficiently? | Store events in a searchable index |

### Data quality checks

A SOC analyst or SIEM engineer should periodically check:

- Are expected hosts sending data?
- Are there ingestion gaps?
- Are timestamps correct?
- Are important fields extracted?
- Are events duplicated?
- Are logs being dropped or throttled?
- Has a source changed its format?
- Is the data volume unexpectedly high or low?
- Are sensitive fields handled according to policy?

A detection cannot work reliably if the required telemetry is missing.

---

## 7. Storage, Indexing, and Search

### 7.1 Important Splunk concepts

| Term | Explanation |
|---|---|
| Index | Logical storage location for indexed events |
| Sourcetype | Describes the format or type of incoming data |
| Source | Identifies the input from which data originated |
| Host | Identifies the originating machine or device |
| Timestamp | Time associated with the event |
| Field | A searchable name/value extracted from an event |
| Forwarder | Component that sends data to Splunk |
| Search Head | Interface and search-management role in a distributed deployment |
| Indexer | Processes and stores indexed data |

These are Splunk terms. Other SIEM platforms use different architecture and vocabulary.

### 7.2 Search fundamentals

A SIEM search should answer a defined question. Before writing a query, identify:

1. Which data source contains the evidence?
2. Which time range is relevant?
3. Which field identifies the user, host, IP, or process?
4. What behaviour are you trying to find?
5. What result would support or weaken your hypothesis?

Do not assume a field exists. Inspect actual events and confirm the field names in your environment.

---

## 8. Detection Engineering

Detection engineering is the process of designing, implementing, testing, deploying, and maintaining logic that identifies security-relevant behaviour.

### 8.1 Detection lifecycle

1. Define the threat or behaviour to detect.
2. Identify the required data sources and fields.
3. Write a detection hypothesis.
4. Build the query or rule.
5. Test against representative benign and malicious data.
6. Validate timestamps, grouping, thresholds, and exclusions.
7. Map the detection to ATT&CK where appropriate.
8. Document expected results and investigation steps.
9. Deploy and monitor.
10. Tune based on evidence and feedback.
11. Review periodically as systems and attacker behaviour change.

### 8.2 Common detection approaches

**Rule-based detection:** Matches explicit conditions, such as a known malicious hash.

**Threshold-based detection:** Triggers when a count or value crosses a threshold, such as many failed logins within a time window.

**Sequence-based detection:** Detects an ordered series of actions, such as repeated failures followed by a success.

**Correlation-based detection:** Combines events from multiple systems, users, or data sources.

**Anomaly-based detection:** Identifies behaviour that differs from a baseline. An anomaly is a lead for investigation, not proof of compromise.

**Threat-intelligence matching:** Compares observed indicators with trusted intelligence sources, considering confidence, age, and context.

### 8.3 Detection rule components

A mature detection should document:

- Name and unique identifier
- Objective and threat hypothesis
- Data sources and required fields
- Query or rule logic
- Lookback period and schedule
- Threshold and grouping keys
- Severity and confidence
- False-positive considerations
- Exclusions and their justification
- ATT&CK technique mapping
- Investigation and response guidance
- Owner, version, and last review date
- Test cases and known limitations

### 8.4 Threshold design

A threshold should be based on expected behaviour and risk, not chosen arbitrarily.

For example, detecting 10 failed logins in five minutes may be useful in one environment but noisy in another. Consider:

- Normal authentication volume
- Shared systems and service accounts
- VPN and NAT behaviour
- Lockout policy
- Number of users targeted
- Number of source addresses
- Whether a successful login followed
- Asset and account criticality

### 8.5 False-positive reduction

Ways to improve detection quality:

- Confirm the correct data source and fields.
- Establish a baseline.
- Use context such as asset role and account type.
- Group events at the correct level.
- Exclude only validated benign activity.
- Use allowlists with owners and expiry/review dates.
- Correlate multiple signals.
- Tune thresholds with measured evidence.
- Preserve visibility when suppressing repetitive alerts.

Never create broad exclusions simply to make alert counts lower. An exclusion can hide real attacks.

---

## 9. Event Correlation and Investigation Context

Correlation connects records that may be individually unremarkable but collectively meaningful.

### Example: Possible account compromise

1. Many failed logins against one account.
2. A successful login from an unusual source.
3. MFA behaviour inconsistent with the user's normal pattern.
4. A new device or session.
5. Access to a sensitive server.
6. Suspicious process execution on that server.

A useful correlation may join records by:

- User identity
- Host or device identity
- Source or destination IP
- Session ID
- Process ID or process ancestry
- Domain or URL
- File hash
- Time window
- Cloud resource or account ID

### Correlation challenges

- Different timestamp formats and time zones
- NAT and shared IP addresses
- Dynamic IP allocation
- Inconsistent usernames
- Missing or duplicated events
- Clock drift
- Delayed ingestion
- Different field names and schemas
- High event volume

Correlation should account for identity and asset context rather than relying only on an IP address.

---

## 10. Alert Triage and Incident Handling

### 10.1 A repeatable alert-triage workflow

**Step 1 — Read the alert**

Understand the detection name, logic, severity, affected entities, time range, and reason it fired.

**Step 2 — Validate the data**

Open the underlying events. Confirm that the expected fields, timestamps, and source systems are present.

**Step 3 — Identify affected entities**

Determine the user, host, IP address, application, cloud resource, or business service involved.

**Step 4 — Establish context**

Ask whether the activity is expected. Check asset criticality, user role, change windows, known maintenance, and recent related alerts.

**Step 5 — Build a timeline**

Arrange related events chronologically. Separate observed facts from assumptions.

**Step 6 — Scope the activity**

Search for the same user, IP, hash, process, domain, or behaviour across other systems and time periods.

**Step 7 — Assess impact and confidence**

Determine what evidence supports malicious activity, what evidence contradicts it, and what remains unknown.

**Step 8 — Decide and document**

Following the organization's playbook, classify the alert, close it as benign with evidence, continue investigation, or escalate.

**Step 9 — Recommend or perform response**

Containment actions must follow authorization and incident-response procedures. Examples include disabling a compromised account, revoking sessions, blocking an indicator, or isolating an endpoint.

**Step 10 — Record lessons learned**

Capture detection gaps, missing telemetry, tuning opportunities, and follow-up actions.

### 10.2 What to investigate in a brute-force alert

- Which account was targeted?
- How many failures occurred?
- Over what period?
- How many source addresses were involved?
- Was a successful login recorded?
- What was the logon type or authentication method?
- Is the source expected, such as a corporate VPN?
- Was MFA involved?
- Did the account access sensitive resources afterward?
- Were there password resets, group changes, or new sessions?
- Are other accounts or hosts affected?

### 10.3 Severity vs confidence

These are different concepts:

- **Severity:** Potential business or technical impact if the activity is malicious.
- **Confidence:** How strongly the available evidence supports the detection's conclusion.

A high-severity alert may have low confidence and require validation. A high-confidence alert can still have limited impact. Follow the organization's classification model.

---

## 11. Threat Intelligence and MITRE ATT&CK

### 11.1 Threat intelligence

Threat intelligence provides contextual information about threats, including:

- Malicious IP addresses
- Domains and URLs
- File hashes
- Malware families
- Threat actor behaviours
- Campaign information
- Tactics, techniques, and procedures

Intelligence should be evaluated for source reliability, confidence, freshness, relevance, and potential false positives. A reputation match alone does not prove that a host is compromised.

### 11.2 IOC vs IOA

- **IOC:** An observable artifact associated with possible compromise, such as a file hash or malicious domain.
- **IOA:** A behaviour or sequence indicating a possible attack, such as a suspicious script launching an encoded command and connecting externally.

IOCs can become outdated as attackers change infrastructure. Behaviour-based detections can be more resilient, but still require context.

### 11.3 MITRE ATT&CK

MITRE ATT&CK is a knowledge base of adversary tactics and techniques based on observed attacker behaviour.

- **Tactic:** The adversary's objective — the "why".
- **Technique:** The method used to achieve an objective — the "how".
- **Sub-technique:** A more specific form of a technique.
- **Procedure:** A real-world implementation of a technique by an adversary.

Examples of tactics include Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, and Exfiltration.

ATT&CK mapping helps communicate what a detection covers. A mapping is a hypothesis about behaviour, not proof that a particular threat actor performed it.

---

## 12. Threat Hunting

Threat hunting is a proactive, hypothesis-driven search for suspicious activity that may not have triggered existing alerts.

### 12.1 Hunting workflow

1. Develop a hypothesis based on threat intelligence, environment risks, or observed behaviour.
2. Identify the telemetry required.
3. Search for relevant activity.
4. Pivot across users, hosts, processes, and network connections.
5. Validate suspicious findings.
6. Record evidence and limitations.
7. Create or improve detections where useful.
8. Share findings with the SOC team.

### Example hypothesis

"An attacker may be using PowerShell to execute encoded commands on Windows endpoints."

Potential telemetry:

- Process creation events
- Command-line arguments
- Parent and child process relationships
- User and host identity
- Network connections from the process
- EDR detections

A hunt should not assume that every PowerShell process is malicious. Administrators and applications use PowerShell legitimately.

### Threat hunting vs alert triage

| Alert triage | Threat hunting |
|---|---|
| Starts from an alert | Starts from a hypothesis or question |
| Reactive | Proactive |
| Validates a detection | Searches for unknown or undetected activity |
| Usually follows a playbook | May require exploratory pivots |
| Can improve alert disposition | Can discover new detection opportunities |

---

## 13. Advanced SIEM Capabilities

### 13.1 UEBA

**User and Entity Behaviour Analytics (UEBA)** evaluates activity associated with users and entities such as endpoints or service accounts.

Examples:

- A user accesses an unusual volume of files.
- A service account logs in interactively.
- An administrator accesses systems outside their normal pattern.
- A device communicates with unusual destinations.

UEBA can use statistical or machine-learning techniques. Its output is a risk signal that requires contextual investigation.

### 13.2 Risk-based alerting

Instead of generating a separate high-priority alert for every low-level event, risk-based approaches accumulate risk across entities and time.

For example:

- Unusual login: risk contribution
- Suspicious process execution: additional contribution
- Access to a sensitive resource: additional contribution

The combined risk can prioritize an entity for investigation. Risk scores are model-dependent and should not be treated as probabilities unless explicitly calibrated that way.

### 13.3 SOAR and automation

Security Orchestration, Automation, and Response (SOAR) platforms coordinate security tools and automate repeatable workflows.

Possible workflow:

1. SIEM creates an alert.
2. SOAR retrieves related endpoint and identity information.
3. It enriches an IP or hash using approved sources.
4. It creates or updates a case.
5. It notifies the assigned analyst.
6. A response action is performed only when authorized by policy and approval requirements.

Automation should include error handling, audit logs, access controls, and safe rollback procedures where possible.

### 13.4 Machine learning and AI in SIEM

AI/ML can assist with:

- Anomaly detection
- Entity behaviour analysis
- Alert grouping and prioritization
- Natural-language search assistance
- Investigation summaries
- Suggested query generation

Risks include poor-quality training data, model drift, false positives, opaque reasoning, prompt injection through untrusted log content, and overreliance on generated conclusions. Analysts must validate results against source evidence.

### 13.5 Detection-as-code

Detection-as-code applies software engineering practices to detection content:

- Store rules in version control.
- Review changes through pull requests.
- Test queries against sample data.
- Track versions and owners.
- Document dependencies and required fields.
- Deploy through controlled pipelines.
- Roll back faulty changes.

### 13.6 Data tiering and retention

Organizations may retain frequently searched data in faster storage and older data in lower-cost storage. Retention must consider:

- Legal and regulatory obligations
- Business requirements
- Incident investigation needs
- Storage and licensing costs
- Privacy and data minimization
- Access controls and deletion policies

There is no universal retention period suitable for every organization.

---

## 14. SIEM, EDR, XDR, IDS/IPS, and SOAR

| Technology | Primary purpose | Typical visibility |
|---|---|---|
| SIEM | Centralize, search, correlate, and analyze security telemetry | Across many systems and sources |
| EDR | Detect and respond to endpoint threats | Endpoint processes, files, registry, network activity |
| XDR | Correlate detection and response signals across security domains | Endpoint, identity, email, network, cloud, depending on product |
| IDS | Detect suspicious network or host activity | Network or host events |
| IPS | Detect and potentially block suspicious activity inline | Network traffic |
| SOAR | Orchestrate and automate security workflows | Connected tools and response systems |
| Firewall | Enforce network traffic policy | Network connections and rules |

These products can overlap. Their exact capabilities depend on vendor and configuration.

### Example of working together

- Firewall records an unusual outbound connection.
- EDR records a suspicious process initiating that connection.
- SIEM correlates the endpoint and firewall events.
- SOC analyst investigates the alert.
- SOAR creates a case and gathers context.
- An authorized responder isolates the endpoint if evidence and policy justify it.

---

## 15. SIEM Deployment and Operations

### 15.1 Deployment models

- **On-premises:** SIEM infrastructure runs in the organization's data centre.
- **Cloud/SaaS:** The platform is delivered as a cloud service.
- **Hybrid:** Data sources and processing are distributed across on-premises and cloud environments.

### 15.2 Architecture considerations

- Number and type of data sources
- Events per second and data volume
- Ingestion licensing and cost
- Network bandwidth
- Search concurrency and performance
- High availability and disaster recovery
- Retention and archival
- Identity and role-based access control
- Encryption in transit and at rest
- Data residency and privacy
- Integrations and operational ownership

### 15.3 Operational health checks

A SOC should monitor the SIEM itself:

- Last event received per source
- Ingestion delay
- Missing or silent hosts
- Parsing failures
- Dropped or delayed events
- Indexing or storage capacity
- Search failures and latency
- Forwarder health
- Connector/API errors
- Scheduled detection failures
- Changes in event volume

A SIEM that silently stops receiving domain controller logs can create a serious blind spot.

### 15.4 Access control

Use role-based access control and least privilege. Separate administrative duties from analyst duties where possible. Restrict access to sensitive logs, protect credentials and API tokens, and audit changes to detection rules and data pipelines.

---

## 16. SIEM Metrics and Detection Quality

Metrics help teams understand whether the SIEM and SOC processes are effective.

| Metric | What it measures |
|---|---|
| MTTD | Mean Time to Detect |
| MTTA | Mean Time to Acknowledge |
| MTTR | Mean Time to Respond or Recover; define the organization's chosen meaning |
| Alert volume | Number of alerts over a period |
| False-positive rate | Proportion of benign alerts among evaluated alerts, according to the team's definition |
| Detection coverage | Threat behaviours and assets covered by detections |
| Data-source coverage | Expected sources successfully providing useful telemetry |
| Ingestion latency | Delay between event occurrence and availability for analysis |
| Rule health | Whether detections execute successfully and produce expected output |
| Case backlog | Open investigations awaiting action |

Metrics require consistent definitions. A low alert volume is not necessarily good if detections are missing attacks. A high alert volume is not necessarily bad if it reflects a temporary incident or improved visibility.

---

## 17. Investigation and Evidence Handling

A SIEM supports digital investigations by making logs searchable and correlatable. It does not replace forensic acquisition or specialist forensic analysis when those are required.

### 17.1 Evidence-based investigation

For each finding, record:

- What was observed?
- Which system produced the evidence?
- What is the original event timestamp and time zone?
- When was the event ingested?
- Which query or method retrieved it?
- What fields support the conclusion?
- Is the record complete and trustworthy?
- What is a fact, and what is an inference?
- What alternative explanation exists?
- What additional evidence is needed?

### 17.2 Preserve evidence

Follow organizational policy and applicable law. Preserve original records where possible, avoid unnecessary modification, record collection methods, restrict access, and maintain chain-of-custody documentation when required.

For exported evidence, document the export time, source, query, scope, analyst, and integrity verification method. Hashing an exported file can help demonstrate that the copy has not changed since it was hashed; it does not independently prove that the source log was accurate.

### 17.3 Build a timeline

A timeline should include:

| Timestamp (with zone) | Source | Entity | Observed activity | Interpretation |
|---|---|---|---|---|
| 09:01:10 UTC | Domain controller | userA | Failed authentication | Observed failure |
| 09:02:05 UTC | VPN | userA | Successful VPN sign-in | Validate source and MFA |
| 09:04:22 UTC | Endpoint EDR | hostA | Suspicious script execution | Investigate process tree |
| 09:06:40 UTC | Firewall | hostA | Outbound connection | Correlate destination and process |

The entries above are illustrative, not real incident evidence.

---

## 18. Practical Splunk Examples

These examples teach the structure of SPL searches. They are starting points, not universal copy-paste detections. Verify your index, sourcetype, field names, timestamp handling, and data model before using them.

### 18.1 Basic search

```spl
index=main
```

Searches events in the `main` index. Your environment may use another index.

### 18.2 Search Windows failed logons

```spl
index=windows EventCode=4625
| table _time host user Account_Name Workstation_Name IpAddress
| sort - _time
```

The displayed fields are examples. Inspect actual events and replace fields that are not present in your data.

### 18.3 Count failed logons by account

```spl
index=windows EventCode=4625
| stats count as failed_attempts by Account_Name
| sort - failed_attempts
```

### 18.4 Count failures by source address

```spl
index=windows EventCode=4625
| stats count as failures by IpAddress
| sort - failures
```

Do not assume `IpAddress` is the correct field in every Windows event extraction. Confirm the actual field in your events.

### 18.5 Linux SSH failure search

```spl
index=linux "Failed password"
| table _time host _raw
| sort - _time
```

### 18.6 Find process creation events

```spl
index=windows EventCode=4688
| table _time host New_Process_Name Creator_Process_Name Process_Command_Line
| sort - _time
```

Process command-line logging must be enabled and correctly collected for the field to be available.

### 18.7 Count events by host and sourcetype

```spl
index=*
| stats count by host sourcetype
| sort - count
```

Use a suitable time range and permissions. Broad searches can be expensive.

### 18.8 Search for a successful logon

```spl
index=windows EventCode=4624
| table _time host TargetUserName Logon_Type IpAddress
| sort - _time
```

### 18.9 A basic threshold example

```spl
index=windows EventCode=4625
| bin _time span=5m
| stats count as failures by _time IpAddress TargetUserName
| where failures >= 10
| sort - failures
```

This groups failures into five-minute time buckets. It is a simple learning example; production logic should account for sliding windows, source quality, account and asset context, NAT, and alert suppression.

### 18.10 SPL concepts to learn

| SPL command | Purpose |
|---|---|
| `search` | Filter events |
| `table` | Display selected fields |
| `fields` | Keep or remove fields |
| `stats` | Aggregate events |
| `timechart` | Build time-based statistics |
| `top` | Show most frequent values |
| `rare` | Show least frequent values |
| `sort` | Sort results |
| `dedup` | Remove duplicate field combinations |
| `eval` | Create or calculate fields |
| `where` | Filter using expressions |
| `bin` | Group numeric or time values into buckets |
| `transaction` | Group related events; use carefully due to performance and semantics |
| `lookup` | Add information from a lookup table |
| `rex` | Extract fields using regular expressions |

### 18.11 KQL awareness

Microsoft Sentinel uses Kusto Query Language (KQL). A simple illustrative query:

```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress
| order by FailedAttempts desc
```

Table and field availability depend on the connector, workspace, and data schema. Learn the schema before writing production queries.

---

## 19. Common SIEM Use Cases

| Use case | Data sources | Example detection idea |
|---|---|---|
| Brute force | Windows, Linux, identity provider, VPN | Repeated authentication failures |
| Password spraying | Identity and authentication logs | One source trying a small set of passwords across many accounts, inferred from failures |
| Suspicious successful login | Identity, VPN, endpoint | Success after repeated failures or unusual context |
| Privilege escalation | Windows, Linux, IAM | Unexpected privileged group or role change |
| New account creation | Directory and cloud audit logs | Unexpected account creation |
| Suspicious PowerShell | Windows process logs, EDR | Unusual command-line or parent-child process behaviour |
| Malware execution | EDR, endpoint, DNS, firewall | Malicious file or suspicious process behaviour |
| Lateral movement | Authentication, endpoint, network | Unusual remote logons or administrative activity |
| Data exfiltration | Proxy, firewall, DNS, cloud | Unusual outbound volume or destination |
| Phishing | Email security, proxy, endpoint | Malicious attachment, URL click, or follow-on execution |
| DNS tunnelling | DNS logs, network telemetry | Unusual query patterns or volume |
| Cloud account misuse | Cloud audit and identity logs | Unusual API or administrative activity |
| Disabled security control | Endpoint and security product logs | Unexpected logging, firewall, or EDR service change |

Every use case needs a documented hypothesis, data requirements, logic, tuning, and investigation steps.

---

## 20. Limitations and Common Challenges

1. **Incomplete visibility:** Missing data sources create blind spots.
2. **Poor data quality:** Incorrect timestamps, missing fields, or parser failures weaken detections.
3. **Alert fatigue:** Excessive low-value alerts reduce analyst effectiveness.
4. **False positives:** Legitimate administrative activity can resemble malicious behaviour.
5. **False negatives:** Poor logic or missing telemetry can allow attacks to go undetected.
6. **Cost:** Ingestion, storage, licensing, and operations can be expensive.
7. **Complexity:** Large environments require careful architecture and maintenance.
8. **Encrypted traffic:** Network visibility may be limited without endpoint or metadata telemetry.
9. **Evasion:** Attackers may disable logging, blend into normal activity, or use legitimate tools.
10. **Retention gaps:** Relevant data may have expired or been archived.
11. **Overreliance on automation:** Automated conclusions and actions need safeguards and human oversight.
12. **Context limitations:** An IP reputation or anomaly score alone is not sufficient to declare an incident.

---

## 21. SOC Analyst Interview Questions

Use these questions for revision. Practise explaining each answer in your own words and support technical answers with examples.

### Fundamentals

**1. What is SIEM?**  
A platform and capability for centralizing, searching, analyzing, and correlating security telemetry to support threat detection, investigation, and response.

**2. Why is SIEM important?**  
It provides centralized visibility, enables cross-source correlation, supports alerting and investigation, and helps retain security records.

**3. What is the difference between a log and an event?**  
An event is an occurrence; a log is a record or message that documents it. In everyday SIEM usage, the terms may overlap.

**4. What is the difference between an event, alert, and incident?**  
An event records activity; an alert flags activity that matches detection logic; an incident is a security case requiring investigation or response.

**5. What is correlation?**  
Connecting related records using time, identity, host, IP, process, session, or other attributes to identify a broader pattern.

**6. What is a false positive? What is a false negative?**  
A false positive flags benign activity; a false negative fails to detect malicious activity.

### Architecture and data

**7. Explain the SIEM data pipeline.**  
Sources generate telemetry; collection brings it in; parsing extracts fields; normalization standardizes them; enrichment adds context; storage makes it searchable; analytics and detection create alerts for investigation.

**8. What is a forwarder?**  
A component that collects or receives data and sends it to a central platform. In Splunk, Universal Forwarder is a lightweight forwarding component.

**9. What is normalization?**  
Mapping fields from different sources into a consistent schema so searches and detections can operate across them.

**10. What is enrichment?**  
Adding context such as asset ownership, user details, threat reputation, or geolocation.

**11. Why is time synchronization important?**  
Accurate timestamps allow events from different systems to be ordered and correlated correctly.

**12. What is the difference between an index, sourcetype, source, and host in Splunk?**  
Index is the logical storage location; sourcetype describes event format; source identifies the input; host identifies the originating machine.

### Detection and investigation

**13. What is a detection use case?**  
A defined security monitoring objective with required telemetry, detection logic, expected output, tuning, and investigation guidance.

**14. What is threshold-based detection?**  
A rule that triggers when a count or measurement crosses a configured threshold within a time period.

**15. What is anomaly-based detection?**  
Detection of behaviour that deviates from a baseline. An anomaly requires investigation and is not proof of an attack.

**16. How would you investigate a brute-force alert?**  
Validate the alert and time range, identify accounts and sources, count failures, look for successful logins, review authentication context, correlate endpoint and network activity, scope affected systems, and document findings.

**17. What would you do if an alert has no supporting raw events?**  
Check time range, index, permissions, data latency, source health, parsing, and the detection query. Record the evidence gap and escalate if required.

**18. How do you reduce false positives?**  
Validate fields, understand normal behaviour, add context, tune thresholds, correlate signals, and use narrow, documented, reviewed exclusions.

**19. What is threat hunting?**  
A proactive, hypothesis-driven search for threats that may not have triggered existing detections.

**20. What is MITRE ATT&CK?**  
A knowledge base describing adversary tactics and techniques, used to understand behaviour and communicate detection coverage.

### Advanced concepts

**21. What is UEBA?**  
Analytics that identify unusual behaviour associated with users and entities based on context and behavioural baselines.

**22. What is risk-based alerting?**  
A method that combines risk signals over time or across events to prioritize entities and investigations.

**23. What is SOAR?**  
Security Orchestration, Automation, and Response; it coordinates tools and automates repeatable workflows under defined permissions and approvals.

**24. SIEM vs EDR?**  
SIEM centralizes and correlates telemetry from many sources; EDR focuses on endpoint detection and response.

**25. SIEM vs XDR?**  
SIEM emphasizes broad data collection, search, correlation, and analytics; XDR emphasizes integrated detection and response across multiple security domains. Product capabilities can overlap.

**26. What is detection-as-code?**  
Managing detection logic with version control, review, testing, documentation, and controlled deployment.

**27. What is ingestion latency?**  
The delay between an event occurring and becoming available in the SIEM.

**28. What metrics help evaluate a SOC?**  
MTTD, MTTA, MTTR (with a defined meaning), alert quality, data-source coverage, ingestion latency, detection coverage, and case backlog.

### Scenario questions

**29. A user has 25 failed logins followed by a successful login. Is this automatically a compromise?**  
No. It is suspicious and should be investigated. Validate the source, account, authentication method, user context, and subsequent activity.

**30. A threat-intelligence feed flags an IP as malicious. Is that enough to declare an incident?**  
No. Validate the source and freshness of the intelligence, determine whether the organization communicated with the IP, and inspect related events and context.

**31. A domain controller stops sending logs. Why is this important?**  
It creates a visibility gap in identity and authentication monitoring. Investigate the forwarder, service, network path, configuration, and source health, and notify the responsible team.

**32. You find suspicious PowerShell execution. What do you investigate?**  
User and host, command line, parent and child processes, file and script details, execution time, network connections, EDR alerts, persistence, and related identity activity.

**33. How do you distinguish facts from assumptions in a report?**  
State the observed event and source as evidence. Label interpretations as hypotheses and explain what additional evidence would confirm or reject them.

---

## 22. Glossary

- **AD:** Active Directory, Microsoft's directory service commonly used for identity and access management in Windows environments.
- **API:** Application Programming Interface.
- **ATT&CK:** MITRE knowledge base of adversary tactics and techniques.
- **CIM:** Splunk Common Information Model.
- **DNS:** Domain Name System.
- **EDR:** Endpoint Detection and Response.
- **ECS:** Elastic Common Schema.
- **IOC:** Indicator of Compromise.
- **IOA:** Indicator of Attack.
- **IPS/IDS:** Intrusion Prevention System / Intrusion Detection System.
- **KQL:** Kusto Query Language.
- **MTTD:** Mean Time to Detect.
- **MTTA:** Mean Time to Acknowledge.
- **MTTR:** Mean Time to Respond or Recover, depending on the defined metric.
- **NTP:** Network Time Protocol.
- **SIEM:** Security Information and Event Management.
- **SLA:** Service-Level Agreement.
- **SOAR:** Security Orchestration, Automation, and Response.
- **SOC:** Security Operations Center.
- **SPL:** Search Processing Language used by Splunk.
- **TTP:** Tactics, Techniques, and Procedures.
- **UEBA:** User and Entity Behaviour Analytics.

---

## 23. Study and Practical Checklist

Use this checklist to measure actual understanding, not just reading progress.

### Foundation

- [ ] Explain SIEM without memorizing a definition.
- [ ] Explain why organizations need centralized log monitoring.
- [ ] Differentiate logs, events, alerts, and incidents.
- [ ] Draw the SIEM data pipeline from memory.
- [ ] Explain collection, parsing, normalization, enrichment, and indexing.

### Log analysis

- [ ] Navigate Windows Event Viewer.
- [ ] Explain common Windows authentication and account-management Event IDs.
- [ ] Read Linux authentication logs.
- [ ] Identify SSH failures and successful logins.
- [ ] Interpret firewall, DNS, VPN, and proxy records.
- [ ] Explain why time synchronization matters.

### Splunk and search

- [ ] Identify indexes, hosts, sources, and sourcetypes in a lab.
- [ ] Search for Windows failed logons.
- [ ] Search for Linux SSH failures.
- [ ] Use stats, timechart, eval, where, sort, and table.
- [ ] Aggregate events by user, host, and source address.
- [ ] Validate field names before writing a detection.

### Detection and response

- [ ] Explain threshold, sequence, correlation, and anomaly detections.
- [ ] Investigate a brute-force alert.
- [ ] Investigate a suspicious successful login.
- [ ] Explain false positives and false negatives.
- [ ] Map relevant behaviour to MITRE ATT&CK.
- [ ] Write an evidence-based investigation summary.
- [ ] Explain when and how to escalate.

### Advanced knowledge

- [ ] Explain UEBA and risk-based alerting.
- [ ] Explain SIEM vs EDR vs XDR vs SOAR.
- [ ] Explain threat hunting and detection engineering.
- [ ] Explain data-source health and ingestion latency.
- [ ] Describe detection tuning and detection-as-code.
- [ ] Explain evidence preservation and timeline construction.

---

## 24. Further Learning

Use official documentation as the primary reference because product interfaces and features change.

1. **Splunk Education:** https://www.splunk.com/en_us/training.html
2. **Splunk Search Reference:** https://docs.splunk.com/Documentation/Splunk/latest/SearchReference
3. **Splunk Common Information Model:** https://docs.splunk.com/Documentation/CIM
4. **Microsoft Sentinel documentation:** https://learn.microsoft.com/en-us/azure/sentinel/
5. **Microsoft Kusto Query Language:** https://learn.microsoft.com/en-us/kusto/query/
6. **MITRE ATT&CK:** https://attack.mitre.org/
7. **NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management:** https://csrc.nist.gov/pubs/sp/800/61/r3/final
8. **Elastic Security documentation:** https://www.elastic.co/guide/en/security/current/index.html
9. **Sigma — Generic Signature Format for SIEM Systems:** https://sigmahq.io/

---

## Final Revision: Explain the SIEM in One Minute

A SIEM collects security telemetry from endpoints, servers, identity systems, network devices, cloud platforms, and applications. It parses and normalizes the data, enriches it with useful context, stores it for searching, and applies rules or analytics to identify suspicious activity. When a detection creates an alert, a SOC analyst validates the underlying evidence, correlates related events, determines scope and impact, documents findings, and escalates or responds according to the organization's procedures. The quality of a SIEM depends on reliable data, useful detections, proper tuning, and skilled analysts.

> **Core principle:** Never treat an alert as proof. Validate the evidence, understand the context, build the timeline, and clearly separate facts from assumptions.

---

*Document type: SIEM study notes and SOC interview reference.*  
*Examples are educational. Validate product-specific syntax, field names, data schemas, and response procedures in your own environment.*
