# Day 07 — Threat Detection Engineering and Correlation Rules

> **Learning path:** SOC Analyst Foundations  
> **Level:** Intermediate to advanced  
> **Focus:** Detection logic, IOCs and IOAs, threshold and behavioural detections, correlation, alert quality, MITRE ATT&CK mapping, and detection documentation  
> **Prerequisites:** Day 05 — Splunk SPL Fundamentals; Day 06 — Advanced SPL for SOC Analysts  
> **Practice environment:** Splunk Enterprise or Splunk Free with Windows Security logs and other suitable security telemetry

---

## 1. Learning Objectives

By the end of this lesson, you should understand how to:

- Explain threat detection engineering and its lifecycle.
- Distinguish indicators of compromise (IOCs) from indicators of attack (IOAs).
- Compare threshold-based, rule-based, and behavioural detections.
- Design detection logic using security events and context.
- Write and interpret Splunk SPL detection searches.
- Understand correlation across users, hosts, IP addresses, and time.
- Recognize false positives, false negatives, and detection gaps.
- Assign alert severity using evidence, confidence, and business impact.
- Map observed behaviours to MITRE ATT&CK techniques carefully.
- Document, test, tune, and maintain detection rules.

## 2. What Is Threat Detection Engineering?

**Threat Detection Engineering** is the disciplined process of designing, implementing, validating, deploying, and improving analytics that identify potentially malicious or policy-violating activity.

A SOC receives telemetry from endpoints, servers, identity systems, firewalls, cloud platforms, email systems, and security products. A detection turns that telemetry into a meaningful signal that an analyst can investigate.

For example, a possible account-compromise sequence might include:

1. Repeated failed authentication attempts.
2. A successful logon to the same account.
3. Suspicious process execution on the endpoint.
4. Creation of an unexpected account.
5. Addition of an account to a privileged group.

Each observation needs context. A sequence may justify investigation, but it does not automatically prove that the events were caused by one attacker.

### 2.1 Detection vs alert vs investigation vs incident

| Term | Meaning |
|---|---|
| Detection | Analytic logic that identifies activity meeting defined conditions. |
| Alert | A notification or record generated when a detection matches. |
| Triage | Initial assessment of the alert's validity, priority, and context. |
| Investigation | Detailed examination of related evidence to determine what happened. |
| Incident | A suspected or confirmed security occurrence requiring coordinated handling under the organization's process. |

An alert is not automatically an incident. Analysts validate the alert using evidence, context, and organizational procedures.

## 3. The Detection Engineering Lifecycle

A detection should be treated as a maintained security capability, not merely a search query.

1. **Define the threat:** Describe the behaviour or security objective to detect.
2. **Identify telemetry:** Determine which sources and fields can provide evidence.
3. **Design logic:** Define conditions, grouping, thresholds, time windows, exclusions, and required context.
4. **Implement:** Write the analytic in the SIEM or detection platform.
5. **Validate:** Test with known relevant events and benign activity.
6. **Tune:** Reduce noise while preserving useful detection coverage.
7. **Deploy:** Configure scheduling, alert details, severity, ownership, and routing.
8. **Monitor:** Review alert quality, data health, performance, and missed coverage.
9. **Maintain:** Update logic as systems, attacker behaviour, and telemetry change.

### 3.1 Questions to answer before writing a rule

- What exact behaviour am I trying to detect?
- Which data source records that behaviour?
- Are the required fields reliably extracted?
- What time window is appropriate?
- Should events be grouped by user, host, source IP, or a combination?
- What legitimate activity could produce the same pattern?
- What additional evidence would increase or reduce confidence?
- What should an analyst do when the rule fires?

## 4. IOCs, IOAs, TTPs, and Behaviour

### 4.1 Indicator of Compromise (IOC)

An IOC is an observable artifact associated with malicious activity or a compromise.

Examples:

- A file hash associated with known malware.
- A domain or IP address associated with malicious infrastructure.
- A malicious URL.
- A known malware filename or certificate.

An IOC match is a lead, not proof by itself. Validate source reliability, freshness, context, and the actual activity observed.

### 4.2 Indicator of Attack (IOA)

An IOA describes behaviour that may indicate an attack, rather than relying only on a known artifact.

Examples:

- Repeated authentication failures.
- Unusual PowerShell execution.
- Unexpected creation of an account.
- Suspicious changes to privileged group membership.
- An unusual sequence of process execution and network connections.

Behavioural detections can identify activity involving previously unseen infrastructure, but legitimate administrative activity may look similar.

### 4.3 TTPs

**TTP** means Tactics, Techniques, and Procedures:

- **Tactic:** The attacker's objective, such as Credential Access or Persistence.
- **Technique:** The method used to achieve that objective.
- **Procedure:** The specific implementation or sequence used by an actor.

| Concept | Example |
|---|---|
| IOC | A known malicious file hash |
| IOA | Repeated password failures followed by suspicious access |
| Tactic | Credential Access |
| Technique | Brute Force |
| Procedure | A particular tool or sequence used to attempt passwords |

## 5. Detection Types

### 5.1 Exact-match or indicator-based detection

Matches an event against a known value, such as a malicious hash or domain.

**Strength:** Can be precise when the intelligence is reliable and current.  
**Limitation:** May miss new, modified, or previously unknown infrastructure and artifacts.

### 5.2 Threshold-based detection

Triggers when a count or value crosses a defined threshold.

Example: ten or more failed logons from one IP address within ten minutes.

**Strengths:**
- Straightforward to implement and explain.
- Useful for repeated or high-volume activity.
- Easy to measure and tune.

**Limitations:**
- Attackers can stay below the threshold.
- Legitimate activity can exceed it.
- A count alone does not establish intent.

### 5.3 Behavioural detection

Looks for patterns, sequences, deviations, or combinations of activity.

Examples:
- Many failed logons followed by a successful logon.
- A new account followed by privileged group membership changes.
- An unusual process followed by a suspicious outbound connection.

Behavioural logic needs reliable timestamps, identity and host context, and careful correlation. Similar behaviour can occur during legitimate administration.

### 5.4 Baseline or anomaly detection

Compares activity with an established pattern of normal behaviour for a user, host, or environment.

Examples:
- A user authenticates at an unusual time compared with their normal pattern.
- A server communicates with a destination it has not contacted before.
- A service account suddenly performs interactive logons.

Anomaly does not equal maliciousness. Baselines need sufficient representative data and must account for role changes, maintenance, shifts, and seasonal activity.

## 6. Thresholds, Time Windows, and Grouping

A threshold rule should specify:

- **Metric:** What is counted or measured?
- **Grouping:** Per IP, user, host, process, or combination?
- **Window:** Over what duration?
- **Threshold:** What value triggers the detection?
- **Context:** What additional fields help an analyst investigate?

Example detection objective:

> Identify source IP addresses generating at least ten failed Windows logons against one account within a ten-minute bucket.

Illustrative SPL:

```spl
index=main EventCode=4625
| bin _time span=10m
| stats count AS Failed_Attempts
        dc(TargetUserName) AS Unique_Accounts
        values(TargetUserName) AS Targeted_Accounts
        by IpAddress _time
| where Failed_Attempts >= 10 AND Unique_Accounts = 1
| eval Detection="Possible Brute Force"
| table _time IpAddress Failed_Attempts Unique_Accounts Targeted_Accounts Detection
| sort - Failed_Attempts
```

Explanation:

- `EventCode=4625` selects failed Windows logon events.
- `bin _time span=10m` places events into ten-minute time buckets.
- `stats` calculates a summary for each IP and time bucket.
- `count` counts matching events.
- `dc(TargetUserName)` counts distinct targeted usernames.
- `values(TargetUserName)` lists distinct usernames.
- `where` keeps groups that meet the defined threshold.
- `table` presents investigation-relevant fields.

This is a bucketed threshold rule, not a continuously sliding ten-minute window. Events close to a bucket boundary may be split between buckets. Select the time-window method based on the detection requirement and validate it with representative data.

### 6.1 Possible password-spraying detection

Password spraying attempts one or a small number of passwords against multiple accounts, often to avoid account lockout thresholds.

Illustrative SPL:

```spl
index=main EventCode=4625
| bin _time span=10m
| stats count AS Failed_Attempts
        dc(TargetUserName) AS Unique_Accounts
        values(TargetUserName) AS Targeted_Accounts
        by IpAddress _time
| where Unique_Accounts >= 5 AND Failed_Attempts >= 5
| table _time IpAddress Failed_Attempts Unique_Accounts Targeted_Accounts
| sort - Failed_Attempts
```

Interpretation:
- Multiple distinct accounts are targeted.
- Failures originate from the same source IP and time bucket.
- This pattern may be consistent with password spraying.

Limitations:
- It does not reveal how many distinct passwords were attempted.
- Shared NAT, proxy, VPN, or corporate egress IPs can combine activity from many users.
- Confirm account, source, authentication type, and surrounding events.

## 7. Correlation: Connecting Related Events

Correlation connects records using common fields, time, sequence, and context.

Useful correlation keys include:

- Username or account identifier.
- Source and destination IP address.
- Hostname or endpoint identifier.
- Process ID and parent process ID.
- Session or logon identifier.
- Event timestamp.
- Cloud resource, application, or transaction identifier.

### 7.1 Failed and successful logons

Illustrative search for accounts and IPs with both failed and successful logon events in the selected time range:

```spl
index=main (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) AS Failed_Logins
        count(eval(EventCode=4624)) AS Successful_Logins
        by IpAddress TargetUserName
| where Failed_Logins >= 5 AND Successful_Logins >= 1
| table IpAddress TargetUserName Failed_Logins Successful_Logins
```

This identifies matching IP/account pairs with both event types in the search period. It does **not** prove that the successful logon happened after the failures. It also does not establish that the same person generated every event.

For sequence analysis, use reliable event timestamps, sort correctly, and apply a time-aware correlation method. Validate that the source timestamp is correctly represented by Splunk's `_time`.

### 7.2 New account followed by group membership change

Relevant Windows Security events include:

| Event ID | Meaning |
|---|---|
| 4720 | A user account was created |
| 4728 | A member was added to a global security group |
| 4732 | A member was added to a local security group |
| 4729 | A member was removed from a global security group |
| 4733 | A member was removed from a local security group |
| 4672 | Special privileges assigned to a new logon |

These events can help investigate account and privilege changes. The exact account fields differ by event. Inspect the raw event and extracted schema before correlating; do not assume that the same field represents the affected account in every event.

### 7.3 Correlation principles

- Use the strongest available identifiers, not just similar usernames.
- Normalize timestamps and account formats.
- Consider time zones and ingestion delay.
- Check whether source IPs represent individual devices or shared gateways.
- Avoid treating proximity in time as proof of causation.
- Preserve the original events so the analyst can inspect the evidence.

## 8. False Positives and False Negatives

### 8.1 False positive

A false positive occurs when benign activity is incorrectly identified as suspicious.

Examples:
- An employee repeatedly enters an incorrect password.
- An approved vulnerability scanner generates unusual connections.
- An administrator runs a legitimate PowerShell script.
- A shared VPN egress IP produces many authentication failures.

### 8.2 False negative

A false negative occurs when malicious activity is not detected.

Examples:
- An attacker stays below a fixed threshold.
- Required endpoint or authentication logs are not collected.
- A detection searches the wrong field name.
- A detection only covers one operating system or authentication method.
- A technique changes and the rule is not updated.

### 8.3 Improving detection quality

- Verify that the correct telemetry is collected.
- Confirm field extraction and normalization.
- Test both malicious-like and benign scenarios.
- Use asset, identity, and business context.
- Tune thresholds using observed environment behaviour.
- Add narrow, justified exclusions rather than broad suppressions.
- Review missed detections and alert feedback.
- Monitor rule performance and data-source health.

Do not tune a rule solely to reduce alert volume. The goal is useful detection with an acceptable balance of coverage, accuracy, and operational cost.

## 9. Detection Severity, Confidence, and Priority

Severity communicates the potential seriousness of the activity. Confidence describes how strongly the available evidence supports the detection. Priority helps determine what should be investigated first.

These concepts are related but not identical.

### 9.1 Example severity levels

| Severity | General meaning | Example |
|---|---|---|
| Critical | Strong evidence of active compromise or major impact | Confirmed compromise of a critical identity or system |
| High | Strongly suspicious activity with significant potential impact | Credible account-compromise indicators |
| Medium | Suspicious activity requiring investigation | Unexpected account or privilege change |
| Low | Weak or limited signal needing context | Small number of unusual authentication failures |
| Informational | Contextual or expected activity | Approved administrative operation |

Organizations define their own severity model. An event ID alone should not determine severity.

### 9.2 Factors affecting priority

- Criticality of the affected asset.
- Privilege level of the account.
- Whether activity is ongoing.
- Strength and reliability of the evidence.
- Scope: one endpoint or many systems.
- Data sensitivity and business impact.
- Availability of containment or mitigation options.

## 10. MITRE ATT&CK Mapping

MITRE ATT&CK is a knowledge base describing adversary tactics and techniques based on observed activity. It helps teams describe and organize detection coverage.

A detection should be mapped to the behaviour it actually identifies. Do not assign a technique merely because a related event exists.

### 10.1 Relevant techniques

| Behaviour | ATT&CK technique |
|---|---|
| Brute-force authentication | T1110 — Brute Force |
| Password spraying | T1110.003 — Password Spraying |
| PowerShell execution | T1059.001 — PowerShell |
| Valid account abuse | T1078 — Valid Accounts |
| Create an account | T1136 — Create Account |
| Account manipulation | T1098 — Account Manipulation |

A Windows Event ID 4625 search can support a brute-force analytic, but the event alone does not prove that the activity is an attack. Likewise, Event ID 4688 alone does not prove malicious PowerShell execution.

Reference: [MITRE ATT&CK](https://attack.mitre.org/).

## 11. Practical Splunk Detection Examples

The examples below assume the relevant fields are extracted and populated. Your uploaded CSV may use different field names or may not contain every field. Inspect events before using a search, and adjust the field names to match your data.

### 11.1 Failed logons grouped by source IP

```spl
index=main EventCode=4625
| stats count AS Failed_Attempts
        dc(TargetUserName) AS Unique_Accounts
        values(TargetUserName) AS Targeted_Accounts
        by IpAddress
| where Failed_Attempts >= 5
| sort - Failed_Attempts
```

This is an all-time-within-the-search-range summary. It is not a time-window detection unless a time bucket or time-aware method is added.

### 11.2 Add IP-level totals while preserving each event

```spl
index=main EventCode=4625
| eventstats count AS Total_Failed_Attempts by IpAddress
| table _time IpAddress TargetUserName Total_Failed_Attempts
```

`eventstats` adds an aggregate field to each original event. Unlike `stats`, it does not collapse the result into one row per IP.

### 11.3 Classify suspicious PowerShell command-line indicators

```spl
index=main EventCode=4688
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line))
| where match(cmd,"-encodedcommand|-enc|frombase64string|downloadstring|invoke-expression")
| table _time Computer TargetUserName ProcessName cmd
```

This assumes one of the listed command-line fields exists. Command-line auditing must be configured for the relevant Windows process-creation telemetry. These strings are investigation indicators, not proof of malicious execution. Validate the process path, parent process, user, script content, destination, and surrounding activity.

### 11.4 Identify account creation events

```spl
index=main EventCode=4720
| table _time Computer TargetUserName
```

Inspect the raw event to identify the account that performed the action and the account that was created. Their field names and meanings must not be assumed to be identical.

### 11.5 Review privilege-related events

```spl
index=main (EventCode=4672 OR EventCode=4728 OR EventCode=4732)
| table _time Computer EventCode TargetUserName
| sort 0 _time
```

Review each event's raw details. Event 4672 concerns special privileges assigned to a logon; 4728 and 4732 concern group membership changes. They are different activities and should not be interpreted as interchangeable.

### 11.6 Create an illustrative risk score

```spl
index=main
| eval Risk_Score=case(
    EventCode=4625, 10,
    EventCode=4672, 30,
    EventCode=4720, 40,
    EventCode=4728, 50,
    EventCode=4732, 50,
    true(), 0
)
| where Risk_Score >= 30
| table _time Computer EventCode TargetUserName Risk_Score
| sort - Risk_Score
```

This is a teaching example only. The numbers are arbitrary and are not a validated production scoring model. A production risk model should account for identity, asset criticality, event context, confidence, duplicate events, and the organization's response process.

## 12. What Makes a Good Detection Rule?

A useful detection should be:

- **Relevant:** Addresses a meaningful threat or security requirement.
- **Evidence-based:** Uses reliable telemetry and well-understood fields.
- **Testable:** Can be validated against representative data.
- **Explainable:** An analyst can understand why it triggered.
- **Actionable:** Provides enough context to guide investigation.
- **Tunable:** Supports justified thresholds and exclusions.
- **Efficient:** Runs within acceptable search and infrastructure limits.
- **Maintained:** Has an owner, review process, and change history.

A query that produces many matches is not necessarily a good detection. The matches must be meaningful and investigateable.

## 13. Detection Rule Documentation Template

Document each production detection with the following information:

| Field | Description |
|---|---|
| Rule name | Clear, unique detection title |
| Objective | Threat behaviour or security condition being detected |
| Data sources | Logs, products, and telemetry required |
| Required fields | Fields used by the detection logic |
| Detection logic | Query, conditions, grouping, and thresholds |
| Time window | Search period, bucket, or sequence window |
| Severity | Organizational severity classification |
| Confidence | Strength of evidence and known limitations |
| ATT&CK mapping | Relevant tactic and technique, if justified |
| False positives | Known benign causes |
| Investigation steps | Context and evidence an analyst should review |
| Response guidance | Escalation or containment guidance under policy |
| Owner | Team or person responsible for the rule |
| Last tested | Date and test evidence |
| Version | Rule revision and change history |

### Example: Windows failed-logon detection

- **Name:** Windows — Repeated Failed Logons by Source IP
- **Objective:** Identify concentrated failed authentication activity.
- **Data source:** Windows Security log.
- **Event ID:** 4625.
- **Grouping:** Source IP and ten-minute time bucket.
- **Illustrative threshold:** Ten or more failures.
- **Potential mapping:** MITRE ATT&CK T1110, when the observed behaviour supports a brute-force interpretation.
- **False positives:** User error, misconfigured services, approved testing, shared egress addresses.
- **Investigation:** Review account names, logon type, source host, destination host, subsequent successful logons, and identity context.
- **Limitation:** A threshold match is suspicious activity, not confirmation of compromise.

## 14. Common Detection Engineering Mistakes

1. **Assuming field names:** A search silently fails or produces incomplete results when field names differ from the actual data.
2. **Ignoring data coverage:** A rule cannot detect events that are not collected.
3. **Using arbitrary thresholds:** Thresholds should be validated against the environment and threat objective.
4. **Ignoring time:** A count across several days is not equivalent to a burst of activity in ten minutes.
5. **Overusing exclusions:** Broad exclusions can hide real attacks.
6. **Treating an IOC match as proof:** Intelligence can be stale, inaccurate, or context-dependent.
7. **Mapping ATT&CK without evidence:** A technique mapping should describe the behaviour actually detected.
8. **Confusing alert severity with confidence:** A severe potential impact does not mean the evidence is conclusive.
9. **Ignoring shared infrastructure:** NAT, proxies, VPN gateways, and service accounts can complicate attribution.
10. **Failing to maintain rules:** Data schemas, operating systems, and attacker techniques change over time.

## 15. SOC Interview Questions and Answers

### Q1. What is threat detection engineering?

It is the process of designing, testing, deploying, and maintaining analytics that identify suspicious or malicious activity using security telemetry.

### Q2. What is the difference between IOC and IOA?

An IOC is an artifact associated with compromise, such as a malicious hash or IP address. An IOA is behaviour that may indicate an attack, such as suspicious authentication or process activity.

### Q3. What is threshold-based detection?

It identifies activity that exceeds a defined value within a specified scope or time period, such as ten failed logons from one IP in ten minutes.

### Q4. What is behavioural detection?

It identifies patterns, sequences, or deviations in activity, often by correlating multiple events and context.

### Q5. What is a false positive?

A benign event or activity that is incorrectly identified as suspicious by a detection.

### Q6. What is a false negative?

Malicious activity that a detection fails to identify.

### Q7. How would you detect password spraying?

I would examine failed authentication events grouped by source IP and time window, count distinct targeted accounts, and investigate repeated failures across multiple accounts. I would validate the source, authentication type, and surrounding activity before concluding that it is password spraying.

### Q8. How do you reduce false positives?

I would validate telemetry and field extraction, understand normal activity, add relevant asset and identity context, tune thresholds using evidence, and create narrow, justified exclusions. I would also test that tuning does not hide relevant malicious behaviour.

### Q9. Why is correlation important?

Individual events may provide limited context. Correlation connects activity across users, hosts, IP addresses, processes, and time to help analysts reconstruct a possible attack sequence.

### Q10. Does an alert confirm an incident?

No. An alert is a signal generated by detection logic. An analyst must validate it using evidence and the organization's incident criteria.

### Q11. Why map detections to MITRE ATT&CK?

Mapping provides a common language for describing observed adversary behaviour, organizing detection coverage, identifying gaps, and communicating with security teams.

### Q12. What information should a detection alert contain?

At minimum, a useful alert should include the detection name, timestamp, affected user and host, relevant source or destination, matched events, severity, reason for triggering, and investigation guidance where available.

## 16. Glossary

| Term | Meaning |
|---|---|
| Detection engineering | Building and maintaining analytics to identify suspicious activity |
| IOC | Indicator of Compromise |
| IOA | Indicator of Attack |
| TTP | Tactics, Techniques, and Procedures |
| Threshold | Defined value that triggers a rule |
| Time window | Period over which activity is evaluated |
| Correlation | Connecting related events and context |
| Baseline | Description of expected normal activity |
| Anomaly | Activity that differs from an established pattern |
| False positive | Benign activity incorrectly flagged |
| False negative | Malicious activity not detected |
| Tuning | Improving detection quality and reducing noise |
| Suppression | Preventing repeated or unwanted alert generation under defined conditions |
| Enrichment | Adding contextual information to events |
| Telemetry | Observable system, user, application, or network data |
| ATT&CK | MITRE knowledge base of adversary tactics and techniques |

## 17. Further Learning and Official References

- [MITRE ATT&CK](https://attack.mitre.org/) — tactics, techniques, and adversary behaviour.
- [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/) — detection strategy knowledge base.
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) — SPL command reference.
- [Splunk Security Content](https://github.com/splunk/security_content) — community and Splunk detection content, analytic stories, and security research.
- [Sigma Rules](https://github.com/SigmaHQ/sigma) — generic, vendor-agnostic detection rule format and community rules.

---

## Key Takeaways

- Detection engineering is a lifecycle: define, design, implement, test, tune, deploy, monitor, and maintain.
- IOCs describe artifacts associated with compromise; IOAs describe suspicious behaviour.
- Threshold detections identify counts or values crossing a defined limit.
- Behavioural detections identify patterns, sequences, and deviations.
- Correlation helps reconstruct activity, but correlation alone does not prove causation.
- False positives and false negatives both matter.
- Severity, confidence, and priority are different concepts.
- MITRE ATT&CK mappings should be supported by the behaviour actually observed.
- A production detection needs documentation, validation, ownership, and an investigation path—not just an SPL query.
