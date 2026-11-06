# Day 04 — Splunk Architecture, Data Ingestion and Configuration

## 1. Introduction to Splunk

Splunk is a platform used to collect, search, monitor, analyse and visualise machine-generated data. In a Security Operations Centre (SOC), it is commonly used as a Security Information and Event Management (SIEM) platform.

Splunk can bring together data from endpoints, servers, network devices, applications, identity systems and cloud services. Security analysts use this data to investigate suspicious activity, identify patterns, create detections, monitor alerts and support incident response.

### Common SOC uses

- Centralise logs from multiple systems.
- Search and investigate security events.
- Detect suspicious authentication and endpoint activity.
- Correlate events from different data sources.
- Build dashboards and scheduled reports.
- Generate alerts when defined conditions are met.
- Support incident investigation and threat hunting.

A SIEM is only as useful as the quality, coverage and reliability of the data it receives. Correct data collection and ingestion are therefore essential.

---

## 2. Splunk Architecture Overview

A Splunk deployment can contain several components. In a small lab, multiple roles may run on one Splunk Enterprise instance. In a larger organisation, the roles are commonly distributed across different servers.

The main components are:

| Component | Main responsibility |
|---|---|
| Universal Forwarder | Collects data from endpoints and forwards it to Splunk |
| Heavy Forwarder | Receives and processes data before forwarding it |
| Indexer | Processes, indexes and stores incoming data |
| Search Head | Provides the interface for searching, reporting and dashboards |
| Deployment Server | Manages configuration deployment to forwarders |
| Cluster Manager | Coordinates an indexer cluster |
| License Manager | Monitors and manages Splunk license usage |

### 2.1 Universal Forwarder (UF)

The Universal Forwarder is a lightweight Splunk component installed on systems that generate logs.

Its primary purpose is to collect selected data and securely forward it to a Splunk receiving component, commonly an indexer or heavy forwarder.

**Key characteristics:**

- Designed for low resource usage.
- Commonly installed on Windows and Linux endpoints and servers.
- Monitors configured log files and supported event sources.
- Forwards data to a configured destination.
- Does not provide the full Splunk Enterprise search and indexing experience.

**Example:** A Universal Forwarder installed on a Windows workstation can collect Windows Security events and forward them to a central Splunk indexer.

### 2.2 Heavy Forwarder (HF)

A Heavy Forwarder is a full Splunk Enterprise instance configured primarily to receive, process and forward data.

It can perform additional processing and routing before sending data to an indexer.

**Common capabilities:**

- Receives data from forwarders and other sources.
- Parses and processes incoming events.
- Routes data to different destinations.
- Filters or transforms data according to configuration.
- Can receive data from multiple systems.

A Heavy Forwarder uses more system resources than a Universal Forwarder. It is generally used when an organisation requires an intermediate processing or routing layer.

### 2.3 Indexer

The indexer is responsible for processing incoming data, creating searchable indexes and storing the data.

When data reaches an indexer, Splunk processes it and organises it so that searches can retrieve relevant events.

**Main responsibilities:**

- Receive incoming data.
- Process and index events.
- Store indexed data.
- Manage index buckets and retention settings.
- Respond to search requests from search heads.

An index is a logical location in which Splunk stores data. Organisations often separate data into indexes based on source, environment, department or retention requirements.

Examples of index names include:

- `windows`
- `linux`
- `network`
- `firewall`
- `endpoint`

The names are examples; an organisation defines its own index structure.

### 2.4 Search Head

The Search Head is the Splunk component through which analysts interact with indexed data.

It provides the search interface and coordinates searches against one or more indexers.

**Common responsibilities:**

- Execute SPL searches.
- Display search results.
- Build dashboards and visualisations.
- Create reports and scheduled searches.
- Configure alerts.
- Support security investigations and threat hunting.

In a distributed deployment, the Search Head can send search requests to multiple indexers and combine their results.

### 2.5 Deployment Server

The Deployment Server centrally manages configuration deployment to supported Splunk forwarders.

For example, an administrator can prepare an application containing input and forwarding configurations and deploy it to a group of Universal Forwarders.

This reduces the need to configure every endpoint individually.

### 2.6 Cluster Manager

The Cluster Manager coordinates an indexer cluster. It manages cluster-related activities such as peer coordination and replication of indexed data.

Indexer clustering is generally used in larger deployments to improve availability and resilience. The exact architecture depends on the organisation's requirements and Splunk version.

### 2.7 License Manager

The License Manager monitors license usage across a Splunk deployment.

Splunk licensing is commonly based on the volume of data that is ingested over a defined period. Administrators monitor ingestion volume to manage capacity and avoid exceeding license limits.

---

## 3. How Data Flows Through Splunk

A typical distributed Splunk data flow is:

```
Data Sources
     |
     v
Universal Forwarder
     |
     v
Indexer or Heavy Forwarder
     |
     v
Indexer
     |
     v
Indexed Data
     |
     v
Search Head
     |
     v
Searches, Dashboards, Reports and Alerts
```

### Explanation of the flow

1. **Data generation:** Endpoints, servers, applications and network devices generate logs and events.
2. **Collection:** A forwarder or another supported input method collects the data.
3. **Forwarding:** The collected data is sent to a configured Splunk receiving component.
4. **Processing:** Splunk processes the incoming data. Depending on the architecture, parsing and other processing may occur on an intermediate heavy forwarder or indexer.
5. **Indexing:** The indexer organises and stores the events in the appropriate index.
6. **Searching:** Analysts use a Search Head to search the indexed data.
7. **Detection and reporting:** Searches can be used to create dashboards, reports and alerts.

Not every deployment has a separate Heavy Forwarder. A simple deployment may send data directly from Universal Forwarders to an indexer.

---

## 4. Data Ingestion Methods

Data ingestion is the process of bringing data into Splunk so that it can be processed, indexed and searched.

Splunk supports several methods of collecting data. The appropriate method depends on the source system, data format, network architecture and operational requirements.

### 4.1 File and Directory Monitoring

Splunk can monitor files and directories for new data.

For example, a Linux server may generate authentication logs in:

`/var/log/auth.log`

A Splunk input can monitor this file and send new log events for indexing.

### 4.2 Windows Event Log Collection

Splunk can collect supported Windows Event Logs, including Security, System and Application logs.

In a Windows environment, a Universal Forwarder can be configured to collect selected event channels.

Examples of useful SOC sources include:

- Windows Security
- Windows System
- Windows PowerShell
- Microsoft Defender-related event channels, where configured and available

### 4.3 TCP and UDP Inputs

Splunk can listen for data sent over TCP or UDP.

This can be useful for receiving logs from network devices, appliances and applications. TCP and UDP inputs must be configured according to the source system and the organisation's network and security requirements.

### 4.4 Syslog

Syslog is a common standard for transmitting log messages from network devices, Linux systems, firewalls and other infrastructure.

Commonly used Syslog ports are:

| Transport | Common port | Description |
|---|---:|---|
| UDP | 514 | Traditional Syslog over UDP |
| TCP | 514 | Syslog over TCP |
| TLS | 6514 | Common port for Syslog over TLS |

These are common conventions, not fixed requirements. Actual ports depend on the device and configuration.

In many environments, a dedicated Syslog server or collector receives Syslog messages and forwards them to Splunk.

### 4.5 HTTP Event Collector (HEC)

The HTTP Event Collector allows applications and supported services to send event data to Splunk over HTTP or HTTPS.

HEC is useful when an application can send structured events directly but does not require a traditional forwarder.

It commonly uses a token to authenticate incoming requests. The HEC listener commonly uses port 8088 by default, although the configured port can differ.

---

## 5. Important Splunk Configuration Files

Splunk uses configuration files to define how data is collected, forwarded, processed, stored and managed.

These files are generally stored in an app's `local` or `default` configuration directory, or in the relevant Splunk system configuration directory.

| Configuration file | Purpose |
|---|---|
| `inputs.conf` | Defines data inputs and collection settings |
| `outputs.conf` | Defines forwarding destinations and output groups |
| `props.conf` | Defines event processing and parsing behaviour |
| `transforms.conf` | Defines transformations, routing and filtering rules |
| `indexes.conf` | Defines index settings, storage and retention behaviour |
| `server.conf` | Defines general server and Splunk instance settings |
| `limits.conf` | Defines operational limits for selected Splunk functions |

The behaviour of a configuration depends on the setting, the component on which it is deployed and Splunk's configuration precedence rules. Changes should be tested and deployed carefully.

### 5.1 inputs.conf

The `inputs.conf` file defines what data Splunk collects and how it collects it.

**Example: monitoring a Linux authentication log**

```ini
[monitor:///var/log/auth.log]
disabled = 0
index = linux
sourcetype = linux_secure
```

Explanation:

- `monitor://` tells Splunk to monitor a file or path.
- `/var/log/auth.log` is the file being monitored.
- `disabled = 0` enables the input.
- `index = linux` sends the data to the `linux` index.
- `sourcetype = linux_secure` identifies the type and format of the incoming data.

The index and sourcetype must be appropriate for the environment. The target index must exist or be configured to accept the data.

### 5.2 outputs.conf

The `outputs.conf` file defines where a forwarder sends collected data.

**Example: forwarding data to an indexer**

```ini
[tcpout]
defaultGroup = splunk_indexer

[tcpout:splunk_indexer]
server = 192.0.2.10:9997
```

Explanation:

- `[tcpout]` defines the general TCP forwarding configuration.
- `defaultGroup` identifies the default forwarding group.
- `[tcpout:splunk_indexer]` defines a named destination group.
- `server` specifies the receiving server and port.

The address `192.0.2.10` is an example documentation IP address. It must be replaced with the actual receiving server address in a real deployment.

The receiving Splunk instance must also be configured to accept forwarded data on the corresponding port.

### 5.3 props.conf

The `props.conf` file defines how Splunk handles data associated with a source type, source or host.

Depending on the configuration and processing stage, it can control settings such as:

- Timestamp recognition.
- Line breaking and event boundaries.
- Character encoding.
- Field extraction behaviour.
- Reference to transformation rules.

It is important because raw data must be interpreted correctly for reliable searching and analysis.

### 5.4 transforms.conf

The `transforms.conf` file defines transformation rules that can be referenced by other configuration settings.

It can support tasks such as:

- Extracting or rewriting fields.
- Routing events to different destinations.
- Filtering or discarding selected events.
- Modifying event metadata.

It is often used together with `props.conf`.

### 5.5 indexes.conf

The `indexes.conf` file defines index properties.

Settings may include:

- Index storage locations.
- Data retention periods.
- Bucket behaviour.
- Index size limits.
- Other index-specific storage and management settings.

Retention settings should be planned carefully because they affect storage capacity and how far back investigators can search.

---

## 6. Important Splunk Ports

The following are common default ports in Splunk Enterprise deployments. Administrators can change them, so always verify the actual configuration.

| Port | Common purpose |
|---:|---|
| 8000 | Splunk Web interface |
| 8089 | Splunk management and REST API |
| 9997 | Receiving forwarded data |
| 8088 | HTTP Event Collector |
| 514 | Common Syslog port; not a universal Splunk default |

### Why these ports matter in a SOC

- Port **8000** is commonly used by analysts and administrators to access Splunk Web.
- Port **8089** is used for management communication and REST API operations.
- Port **9997** is commonly used by indexers or receiving components to accept forwarded data.
- Port **8088** is commonly used by HEC clients to submit event data.
- Port **514** may be used by Syslog devices to send logs to a collector.

A port being reachable does not by itself prove that a service is correctly configured or that data is successfully arriving.

---

## 7. Single-Instance and Distributed Deployments

### 7.1 Single-Instance Deployment

In a small lab or basic environment, one Splunk Enterprise instance may perform several roles:

- Receive data.
- Index and store data.
- Provide the search interface.
- Run searches, dashboards and alerts.

**Advantages:**

- Simple to install and manage.
- Suitable for learning and testing.
- Requires fewer systems.

**Limitations:**

- Limited scalability.
- More resources are shared by different functions.
- A failure can affect the entire deployment.

### 7.2 Distributed Deployment

In a larger environment, Splunk components are separated across multiple systems.

For example:

- Universal Forwarders collect data from endpoints.
- Heavy Forwarders perform intermediate processing.
- Indexers store and manage indexed data.
- Search Heads provide analyst access.
- A Deployment Server manages forwarder configurations.
- A Cluster Manager coordinates an indexer cluster.

**Advantages:**

- Better scalability.
- Separation of responsibilities.
- Can support high data volumes.
- Can improve resilience when designed appropriately.

The architecture should be based on ingestion volume, search demand, retention requirements, availability needs and operational complexity.

---

## 8. Indexes, Sourcetypes, Sources and Hosts

These terms are important when understanding how Splunk organises incoming data.

| Term | Meaning | Example |
|---|---|---|
| Index | Logical location where events are stored | `linux` |
| Sourcetype | Identifies the format or type of data | `linux_secure` |
| Source | Identifies the specific input from which data came | `/var/log/auth.log` |
| Host | Identifies the system that generated the event | `ubuntu-server` |

These fields help analysts narrow searches and understand where events originated.

For example, an authentication event may have:

- Index: `linux`
- Sourcetype: `linux_secure`
- Source: `/var/log/auth.log`
- Host: `ubuntu-server`

The exact values depend on the input and configuration.

---

## 9. Common Data Ingestion Problems

A Splunk input can be configured but still fail to produce searchable data. Analysts and administrators should understand common causes.

| Problem | Possible cause |
|---|---|
| No events appear | Input is disabled, incorrect path, or source is not generating logs |
| Forwarder cannot connect | Network issue, incorrect destination or receiving port not enabled |
| Data reaches the wrong index | Incorrect index assignment or routing configuration |
| Events have an unexpected sourcetype | Incorrect or missing sourcetype configuration |
| Events are split incorrectly | Event boundary or line-breaking configuration issue |
| Timestamps are incorrect | Timestamp recognition, timezone or source clock issue |
| Data arrives late | Network delay, buffering or forwarding backlog |
| Some logs are missing | Permissions, collection configuration, filtering or source-side retention |

### Important troubleshooting considerations

1. Confirm that the source system is generating the expected logs.
2. Confirm that the input is enabled and points to the correct source.
3. Check that the forwarder is running and configured with the correct destination.
4. Confirm network connectivity and that the receiving component accepts data.
5. Verify the index and sourcetype assigned to the data.
6. Review Splunk internal logs and relevant component logs for errors.
7. Check timestamps, time zones and event parsing when events are present but difficult to locate.

Troubleshooting should follow the data path from the original source to the final searchable event.

---

## 10. Why Splunk Architecture Matters to a SOC Analyst

A SOC analyst does not normally administer every part of a Splunk deployment, but understanding the architecture helps explain data availability and investigation limitations.

For example:

- If Windows Security logs are missing, the issue may be at the endpoint input or forwarder.
- If a forwarder is connected but data is not searchable, the issue may involve receiving, indexing, routing or index selection.
- If events appear under an unexpected sourcetype, searches and field extractions may not behave as expected.
- If timestamps are incorrect, an investigation using a time range may overlook relevant events.
- If retention is limited, older evidence may no longer be available.

A reliable investigation depends on knowing whether the SIEM has the required data, whether the data is correctly processed and whether the relevant time period is retained.

---

## 11. Important Terminology

| Term | Definition |
|---|---|
| Data ingestion | Bringing data into Splunk |
| Forwarder | Component that collects and sends data |
| Universal Forwarder | Lightweight data collection and forwarding component |
| Heavy Forwarder | Splunk instance capable of additional data processing and forwarding |
| Indexer | Component that processes, indexes and stores data |
| Search Head | Component used to search and analyse indexed data |
| Index | Logical location used to store events |
| Sourcetype | Label that identifies the type or format of incoming data |
| HEC | HTTP-based method for sending event data to Splunk |
| Parsing | Processing raw data into events and interpreting its structure |
| Retention | Period for which indexed data is kept |
| Deployment Server | Central configuration deployment component for supported forwarders |
| Cluster Manager | Component that coordinates an indexer cluster |

---

## 12. Common Interview Questions and Answers

### 1. What is Splunk?

Splunk is a platform used to collect, search, monitor, analyse and visualise machine-generated data. In a SOC, it is commonly used as a SIEM to investigate security events and detect suspicious activity.

### 2. What is the difference between a Universal Forwarder and a Heavy Forwarder?

A Universal Forwarder is a lightweight component mainly used to collect and forward data. A Heavy Forwarder is a full Splunk Enterprise instance that can perform additional parsing, filtering, transformation and routing before forwarding data.

### 3. What is an indexer?

An indexer receives data, processes it, creates searchable indexes and stores the events.

### 4. What is a Search Head?

A Search Head provides the interface for searching indexed data and creating dashboards, reports and alerts.

### 5. What is the purpose of inputs.conf?

It defines the data sources Splunk collects and the settings used to collect that data.

### 6. What is the purpose of outputs.conf?

It defines the destinations to which a forwarder sends collected data.

### 7. What is the difference between an index and a sourcetype?

An index identifies where events are stored. A sourcetype identifies the type or format of the incoming data.

### 8. What is the Splunk receiving port commonly used by forwarders?

Port 9997 is commonly used for receiving forwarded data, although the port can be changed.

### 9. What is HEC?

HTTP Event Collector is a Splunk feature that allows applications and supported services to send event data through HTTP or HTTPS using an authentication token.

### 10. What is the difference between a single-instance and distributed deployment?

A single-instance deployment performs multiple Splunk roles on one system. A distributed deployment separates roles across multiple systems to support scalability, performance and resilience.

### 11. What could cause logs not to appear in Splunk?

Possible causes include an inactive input, incorrect file path, stopped forwarder, network connectivity problems, incorrect receiving configuration, permissions, routing issues or an incorrect index assignment.

### 12. Why is data ingestion important in a SOC?

Detection and investigation depend on the availability of accurate and relevant telemetry. If important logs are not collected, the SOC may miss suspicious activity or lack the evidence needed to investigate an incident.

---

## 13. Key Points to Remember

- Splunk is widely used as a SIEM platform for security monitoring and investigation.
- A Universal Forwarder collects and forwards data from endpoints.
- A Heavy Forwarder can perform additional processing and routing.
- An Indexer processes, indexes and stores incoming data.
- A Search Head is used for searches, dashboards, reports and alerts.
- A Deployment Server manages supported forwarder configurations.
- A Cluster Manager coordinates an indexer cluster.
- `inputs.conf` defines data collection.
- `outputs.conf` defines forwarding destinations.
- `props.conf` and `transforms.conf` support event processing and transformations.
- `indexes.conf` defines index settings.
- Port 9997 is commonly used for forwarded data, while 8088 is commonly used for HEC.
- Index, sourcetype, source and host describe different aspects of an event.
- Missing or incorrectly parsed logs can create visibility gaps during security investigations.

---

## 14. Official Documentation

- [Splunk Enterprise Documentation](https://docs.splunk.com/Documentation/Splunk)
- [Splunk Forwarding Data](https://docs.splunk.com/Documentation/Splunk/latest/Forwarding/Forwardingdata)
- [Universal Forwarder Documentation](https://docs.splunk.com/Documentation/Forwarder)
- [Configure Data Inputs](https://docs.splunk.com/Documentation/Splunk/latest/Data/Configureyourinputs)
- [Configure HTTP Event Collector](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector)

---

*End of Day 04 — Splunk Architecture, Data Ingestion and Configuration.*
