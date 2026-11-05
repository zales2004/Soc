# Day 03 — Log Collection, Parsing, Normalization & Enrichment

> **SOC Analyst Learning Path · Day 03**  
> Focus: How security data moves from its original source into a SIEM and becomes useful for detection and investigation.

## Learning objectives

By the end of this topic, you should understand:

- How logs are collected from endpoints, servers, network devices, and cloud services.
- The roles of agents, forwarders, Syslog, APIs, and Windows Event Forwarding.
- How parsing extracts fields from raw events.
- Why normalization creates consistency across different data sources.
- How enrichment adds investigative context.
- The meaning of ingestion, indexing, retention, and event timestamps.
- Common causes of missing, delayed, or incorrectly parsed logs.

---

## 1. The security data pipeline

Organizations operate many different systems. Windows, Linux, firewalls, identity platforms, endpoint security products, and cloud services all generate events in different formats.

A Security Information and Event Management (SIEM) platform brings this information together so security teams can search, correlate, detect, and investigate activity.

A simplified data pipeline is:

```
Log Sources
    |
    v
Collection and Transport
    |
    v
Parsing and Field Extraction
    |
    v
Normalization
    |
    v
Enrichment
    |
    v
Indexing and Storage
    |
    v
Detection, Search and Investigation
```

The stages may be combined or occur in a different order depending on the SIEM architecture and data source.

**Key distinction:** A SIEM can only provide visibility into the events it successfully receives and processes. Missing telemetry creates a visibility gap.

## 2. Log collection

Log collection is the process of gathering event data from systems and transporting it to a central platform.

### 2.1 Agent-based collection

An agent is software installed on an endpoint or server. It reads configured logs or telemetry and forwards the data to a central system.

Examples:

- **Splunk Universal Forwarder:** Collects configured data from Windows and Linux systems and forwards it to Splunk.
- **Wazuh Agent:** Collects endpoint security information for analysis by the Wazuh platform.
- Other endpoint and monitoring agents may collect operating-system, application, or security telemetry.

A typical flow:

```
Windows Endpoint
  |
  | Security Event Logs
  v
Splunk Universal Forwarder
  |
  | Forwarded events
  v
Splunk Receiving Component
  |
  v
Splunk Index
```

Agent-based collection depends on agent health, configuration, permissions, connectivity, and the availability of the source logs.

### 2.2 Agentless collection

Agentless collection gathers data without installing a separate collection agent on every source device. The source may send logs directly or expose them through a collection interface.

Common examples include:

- Syslog forwarding from firewalls and network devices.
- API-based collection from cloud and SaaS platforms.
- Windows Event Forwarding (WEF), which centralizes Windows events through Windows event collection infrastructure.

Agentless does not mean that no collector, service, or supporting infrastructure is required.

### 2.3 Syslog

Syslog is a widely used standard for message logging and log transport. It is common on Linux systems, routers, switches, firewalls, and security appliances.

Common transport conventions:

| Transport | Common port | Characteristics |
|---|---:|---|
| UDP | 514 | Connectionless; delivery is not guaranteed |
| TCP | 514 | Connection-oriented transport |
| TLS over TCP | 6514 | Encrypted Syslog transport when configured |

Ports are conventions, not guarantees. The actual device and receiver configuration must be checked.

Syslog messages commonly contain information such as a timestamp, hostname, application or process, and message content. The exact format depends on the Syslog implementation and configuration.

### 2.4 API-based collection

An Application Programming Interface (API) allows one system to request or retrieve data from another system.

SIEM platforms commonly use APIs to collect:

- Cloud audit logs.
- Identity-provider sign-in events.
- SaaS application activity.
- Endpoint security alerts.
- Security findings from other platforms.

API collection requires attention to authentication, permissions, pagination, rate limits, polling intervals, and checkpoints. If an API integration stops working or lacks the correct permissions, events may not arrive.

### 2.5 Collection methods compared

| Method | Typical sources | Important considerations |
|---|---|---|
| Agent / forwarder | Windows and Linux endpoints | Agent status, permissions, configuration, connectivity |
| Syslog | Firewalls, routers, switches, appliances | Transport, receiver configuration, message format |
| API | Cloud and SaaS platforms | Authentication, permissions, rate limits, pagination |
| Windows Event Forwarding | Windows systems | Collector and subscription configuration |
| File monitoring | Applications and services | File paths, access permissions, rotation, format |

### 2.6 Common causes of collection failure

- Forwarder or agent service is stopped.
- Network connectivity is unavailable.
- A firewall blocks the required connection.
- The destination address or receiving port is incorrect.
- The source log channel or file is not configured for collection.
- The collection account lacks required permissions.
- An API token expires or loses permissions.
- A queue, buffer, or storage limit is reached.
- Log rotation changes the file being monitored.

**SOC perspective:** An absence of alerts is not proof that no suspicious activity occurred. First establish whether the relevant telemetry is being collected.

---

## 3. Parsing and field extraction

Parsing is the process of interpreting an event's format and extracting useful information into individual fields.

A log may arrive as plain text, JSON, XML, or another structured or semi-structured format.

### 3.1 Example: raw Linux SSH event

Raw event:

```text
Nov 05 10:15:20 ubuntu sshd[2210]:
Failed password for alen from 192.0.2.40 port 52341 ssh2
```

A parser may extract:

| Field | Example value |
|---|---|
| timestamp | Nov 05 10:15:20 |
| host | ubuntu |
| process | sshd |
| process_id | 2210 |
| action | Failed password |
| username | alen |
| source_ip | 192.0.2.40 |
| source_port | 52341 |
| protocol | ssh2 |

The original event is now easier to search because important values are available as separate fields.

### 3.2 Example: JSON event

JSON is a structured data format that stores information as key-value pairs.

```json
{
  "timestamp": "2026-11-05T10:15:20Z",
  "event_type": "login_failure",
  "username": "alen",
  "source_ip": "192.0.2.40",
  "status": "failure"
}
```

A SIEM can extract JSON keys as fields when the input and parsing configuration are correct.

### 3.3 Important parsing terminology

| Term | Meaning |
|---|---|
| Raw event | Original event data received from the source |
| Field extraction | Identifying and extracting values from an event |
| Parser | Logic or software that interprets a data format |
| Delimiter | Character that separates values, such as a comma |
| Key-value pair | A named field and its value, such as `username=alen` |
| Structured data | Data organized in a defined format, such as JSON or XML |
| Unstructured data | Data primarily represented as free-form text |

### 3.4 Why parsing matters

Parsing makes it possible to filter, group, correlate, and analyze events using individual fields instead of searching only through raw message text.

For example, an analyst can search for events associated with a particular source IP or username, rather than manually reading every message.

**Important:** Parsing extracts information. It does not decide whether an event is malicious.

---

## 4. Normalization

Normalization is the process of mapping different vendor-specific fields and formats into a consistent structure or schema.

Different products may use different names for the same concept.

### 4.1 Example

| Data source | Original field | Value |
|---|---|---|
| Firewall | `src` | 192.0.2.40 |
| EDR | `source_address` | 192.0.2.40 |
| Cloud platform | `clientIpAddress` | 192.0.2.40 |

All three fields describe a source IP address. A normalization layer can map them to a common field, such as:

```text
source.ip = 192.0.2.40
```

Likewise, fields such as `user`, `username`, `user_name`, and `account` may represent a user identity and can be mapped to a common user field.

### 4.2 Common normalized concepts

| Concept | Example schema field |
|---|---|
| Source IP | `source.ip` |
| Destination IP | `destination.ip` |
| Username | `user.name` |
| Hostname | `host.name` |
| Process name | `process.name` |
| Event timestamp | `@timestamp` |
| Event category | `event.category` |
| Event outcome | `event.outcome` |

These are examples of common schema conventions. Exact field names depend on the SIEM and the schema it uses.

### 4.3 Why normalization is important

Normalization helps a SOC team:

1. Search across different data sources consistently.
2. Create detection rules that work across multiple vendors.
3. Correlate related events from endpoints, networks, and cloud services.
4. Build dashboards using consistent fields.
5. Reduce dependence on vendor-specific field names.

### 4.4 Elastic Common Schema (ECS)

Elastic Common Schema (ECS) is a shared field naming and structure standard used in the Elastic ecosystem.

It defines common fields for concepts such as users, hosts, processes, and network connections. Examples include:

```text
source.ip
destination.ip
user.name
host.name
process.name
```

Other SIEM platforms may use different schemas or data models. The underlying goal is similar: provide consistent field names and structures across different data sources.

---

## 5. Enrichment

Enrichment adds useful context to an event so that analysts can better understand its significance and investigate it efficiently.

### 5.1 Example

A raw event might contain:

```text
source_ip = 192.0.2.40
username = alen
event = failed_login
```

Additional information from organizational data sources may provide:

```text
source_ip = 192.0.2.40
username = alen
event = failed_login
asset_name = FINANCE-SERVER-01
asset_criticality = High
user_department = Finance
user_role = Standard
```

The added information helps the analyst understand which account and business asset are involved.

### 5.2 Common enrichment sources

| Source | Context provided |
|---|---|
| Asset inventory / CMDB | Asset owner, system role, criticality |
| Identity directory | Department, account status, group membership |
| Threat intelligence | Indicator reputation and known threat context |
| Geo-IP database | Approximate geographic information associated with an IP |
| Vulnerability scanner | Known vulnerabilities affecting an asset |
| DHCP and DNS records | Hostname and IP relationships |
| Business context | Importance of the system to business operations |

### 5.3 Threat intelligence enrichment

A SIEM or security platform may check an IP address, domain, URL, or file hash against threat-intelligence sources.

Possible results include:

- No known malicious reputation.
- Previously reported in suspicious activity.
- Associated with known malicious infrastructure.
- Insufficient information to determine reputation.

A threat-intelligence match is an investigative clue, not conclusive proof. Analysts should consider the source, confidence, freshness, and surrounding event context.

### 5.4 Geo-IP limitations

Geo-IP databases estimate a geographic location associated with an IP address. They do not reliably establish the physical location of a person or device.

VPNs, proxies, cloud services, mobile networks, and shared gateways can make location-based conclusions misleading.

---

## 6. Ingestion, indexing, and storage

These terms describe how data enters a SIEM and becomes available for searching.

### 6.1 Ingestion

Ingestion is the process of bringing data into a platform. It may involve receiving, reading, or importing records from agents, APIs, files, or network sources.

### 6.2 Indexing

Indexing organizes incoming data so it can be searched efficiently.

In Splunk, event data is stored in indexes. An index is a logical storage location for event data.

Illustrative index names:

```text
index=windows
index=linux
index=firewall
index=endpoint
```

Organizations define their own index naming, access, and retention strategies.

### 6.3 Retention

Retention defines how long event data is kept available.

Retention decisions may depend on:

- Security investigation requirements.
- Legal and regulatory obligations.
- Storage capacity and cost.
- Organizational policy.
- Incident response requirements.

Older events may no longer be immediately searchable if the retention period has expired or the data has been archived.

### 6.4 Event time vs ingestion time

These timestamps are not necessarily the same.

- **Event time:** When the activity occurred according to the source event.
- **Ingestion time:** When the SIEM received or processed the event.

Example:

```text
Event time:     10:15:20
Ingestion time: 10:16:05
```

The event occurred at 10:15:20 and reached the SIEM at 10:16:05. The delay may be caused by buffering, network latency, polling intervals, or processing.

When constructing an incident timeline, analysts must understand which timestamp they are using.

### 6.5 Time synchronization

Inconsistent system clocks can make an incident timeline inaccurate. A Windows server, Linux server, firewall, and SIEM may all report different times if their clocks are not synchronized.

Organizations commonly use Network Time Protocol (NTP) to synchronize system clocks.

Time-related details to consider:

- Time zone and UTC offset.
- Clock synchronization status.
- Source event timestamp.
- SIEM ingestion timestamp.
- Delayed or out-of-order events.

---

## 7. Data quality and visibility

Collected data is only useful when it is sufficiently complete, accurate, timely, and correctly interpreted.

Common data quality problems include:

| Problem | Possible impact |
|---|---|
| Missing logs | Activity may not be visible to the SOC |
| Incorrect timestamps | Investigation timelines may be inaccurate |
| Failed parsing | Important fields may not be searchable |
| Inconsistent field names | Correlation and detection rules may fail |
| Duplicate events | Counts and alert volumes may be misleading |
| Delayed ingestion | Detection and response may be slower |
| Incorrect source metadata | Events may be attributed to the wrong host or system |
| Insufficient retention | Historical evidence may be unavailable |

A SOC analyst should not assume that a data source is healthy simply because it was configured once. Collection and parsing need ongoing monitoring.

## 8. Troubleshooting missing or unusable logs

When expected events are absent from a SIEM, investigate the data path in order:

1. **Source:** Is the source generating the relevant logs?
2. **Configuration:** Is the correct event channel, file, or data type enabled?
3. **Collector:** Is the agent, forwarder, or collection service running?
4. **Connectivity:** Can the source or collector reach the receiving platform?
5. **Permissions:** Does the collection service have access to the required data?
6. **Ingestion:** Is the SIEM receiving the events?
7. **Parsing:** Are the expected fields being extracted?
8. **Time range:** Is the search using the correct event time and time zone?
9. **Storage and retention:** Is the data being routed to the expected index or retained?
10. **Filtering:** Are inputs, transformations, or routing rules dropping the events?

This sequence helps distinguish a source problem from a transport, parsing, or search problem.

---

## 9. How these concepts fit together in Splunk

Splunk provides a practical example of a SIEM data pipeline.

A simplified architecture includes:

| Component | Purpose |
|---|---|
| Data source | Generates logs, such as Windows Security events |
| Universal Forwarder | Collects and forwards configured data |
| Receiver / Indexer | Receives and processes incoming data; indexers store indexed events |
| Search Head | Provides the interface for searching, analyzing, and visualizing data |
| Index | Logical storage location for indexed events |
| Search Processing Language (SPL) | Language used to search and analyze Splunk data |

A typical flow:

```
Windows / Linux / Network Devices
              |
              v
       Data Collection
              |
              v
     Splunk Universal Forwarder
              |
              v
       Splunk Receiver
              |
              v
       Parsing and Indexing
              |
              v
          Splunk Index
              |
              v
       Search Head / SPL
              |
              v
       Detection and Analysis
```

Splunk's exact processing architecture depends on the deployment. For example, parsing and indexing responsibilities can be distributed across forwarders, intermediate components, and indexers depending on the configuration.

---

## 10. Key terminology — quick reference

| Term | Meaning |
|---|---|
| Log source | System or application that generates event data |
| Agent | Software installed on a system to collect or monitor data |
| Forwarder | Component that transports collected data to another platform |
| Syslog | Standard commonly used for system message logging and transport |
| API | Interface that allows systems to exchange or retrieve data |
| Collection | Gathering and transporting event data |
| Ingestion | Bringing data into a platform |
| Parsing | Interpreting raw data and extracting fields |
| Field extraction | Separating useful values into searchable fields |
| Normalization | Mapping different formats and names into a consistent schema |
| Enrichment | Adding contextual information to events |
| Indexing | Organizing data for efficient search |
| Retention | Period for which data is kept |
| Event time | Time the activity occurred |
| Ingestion time | Time the platform received or processed the event |
| Data quality | Accuracy, completeness, consistency, and timeliness of data |

## 11. Important points to remember

- A SIEM depends on reliable telemetry from its connected sources.
- Agents and forwarders collect and transport data; they are not the same thing as the SIEM itself.
- Syslog is common for network devices and appliances.
- APIs are important for cloud and SaaS log collection.
- Parsing extracts useful fields from raw events.
- Normalization maps different vendor fields into a common structure.
- Enrichment adds context that helps analysts assess events.
- Ingestion time and event time can differ.
- NTP helps maintain consistent timestamps across systems.
- Missing logs can create detection blind spots.
- A successful data pipeline requires continuous monitoring and validation.

## 12. Official documentation

- [Splunk Universal Forwarder documentation](https://docs.splunk.com/Documentation/Forwarder)
- [Splunk data onboarding documentation](https://docs.splunk.com/Documentation/Splunk/latest/Data/WhatSplunkcanmonitor)
- [Splunk indexes and index management](https://docs.splunk.com/Documentation/Splunk/latest/Indexer/Aboutindexes)
- [Elastic Common Schema documentation](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html)
- [RFC 5424 — The Syslog Protocol](https://www.rfc-editor.org/rfc/rfc5424)
- [RFC 5425 — TLS Transport Mapping for Syslog](https://www.rfc-editor.org/rfc/rfc5425)
- [Microsoft Windows Event Forwarding documentation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)

---

**Day 03 takeaway:** Log collection brings security data into the SIEM. Parsing makes the data understandable, normalization makes different sources consistent, and enrichment adds context. Together, these processes turn raw logs into reliable information that a SOC analyst can search, correlate, and investigate.
