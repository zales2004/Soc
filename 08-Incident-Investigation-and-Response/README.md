# Day 08 – Incident Investigation and Response

## 1. Introduction

Incident investigation and response is the process of identifying a possible security incident, understanding what happened, limiting its impact, removing the threat, restoring normal operations, and recording what was learned.

A SOC analyst does not simply close alerts. The analyst examines evidence, checks whether activity is suspicious, determines the scope and impact, documents findings, and escalates incidents when required.

**Example:** A SIEM generates an alert for repeated failed logins against an employee account. The analyst checks the source IP, targeted account, time pattern, whether a login eventually succeeded, and what happened after the successful login.

> Important: An alert is a signal that needs investigation. An alert by itself does not prove that a security incident occurred.

## 2. Security Event, Alert, and Incident

These terms are related, but they do not mean the same thing.

| Term | Meaning | Example |
|---|---|---|
| Event | A recorded activity on a system or network | A user logs in |
| Alert | A notification generated when activity matches a detection condition | Five failed logins from one IP |
| Incident | A confirmed or sufficiently suspected security event that requires a coordinated response | An attacker gains access to an employee account |

A single incident may generate many events and alerts. Analysts correlate these records to understand the larger activity.

## 3. Incident Response Lifecycle

A widely used traditional incident-response lifecycle is described in NIST SP 800-61 Revision 2. It contains four main phases.

### Phase 1 – Preparation

Preparation happens before an incident.

Activities include:

- Establishing incident-response policies and procedures.
- Defining roles and escalation contacts.
- Configuring SIEM, EDR, firewalls, and logging.
- Maintaining secure backups.
- Preparing investigation and reporting templates.
- Ensuring that systems use reliable time synchronisation.
- Practising response procedures through exercises.

**SOC example:** Ensure that Windows security logs are collected in Splunk and that analysts know how to contact the incident-response team.

### Phase 2 – Detection and Analysis

The SOC identifies suspicious activity and investigates it.

Activities include:

- Reviewing alerts and their detection logic.
- Checking affected users, hosts, IP addresses, and timestamps.
- Examining related authentication and endpoint events.
- Looking for signs of compromise.
- Determining scope, impact, severity, and confidence.
- Escalating confirmed or high-risk activity.

**SOC example:** Investigate repeated failed logins, identify whether any login succeeded, and inspect activity performed by the account afterwards.

### Phase 3 – Containment, Eradication, and Recovery

This phase limits damage, removes the threat, and restores normal operations.

| Activity | Purpose | Example |
|---|---|---|
| Containment | Limit the incident's spread or impact | Isolate a compromised endpoint |
| Eradication | Remove the cause of the incident | Remove malware and persistence mechanisms |
| Recovery | Restore systems safely | Restore a clean backup and monitor the host |

Actions such as disabling accounts, isolating endpoints, blocking IP addresses, or changing credentials must follow organisational policy and the required approval process. A junior SOC analyst should not take disruptive actions without authorisation.

### Phase 4 – Post-Incident Activity

After the incident, the team reviews what happened and how the response can improve.

Activities include:

- Preparing the final incident report.
- Recording the root cause, impact, and timeline.
- Identifying gaps in logging or detection.
- Improving detection rules and response procedures.
- Recording lessons learned.
- Tracking remediation actions to completion.

**Example:** If an incident succeeded because an account did not have MFA enabled, the organisation may introduce stronger authentication controls.

**Terminology note:** NIST SP 800-61 Revision 3 was published in 2025. It updates the guidance and integrates incident response into the broader cybersecurity risk-management lifecycle. The four-phase model above is the familiar Revision 2 structure and remains useful for learning the response process.

## 4. Alert Triage

Alert triage is the first review of an alert to decide whether it needs further investigation, escalation, or closure.

A SOC analyst should answer these questions:

1. What triggered the alert?
2. Which user, device, application, or network asset is involved?
3. When did the activity happen?
4. What is the source IP or other relevant source?
5. Is the activity expected for this user or system?
6. Are there related alerts or events?
7. Is there evidence of successful compromise?
8. Does the alert need escalation?

### True positive and false positive

| Classification | Meaning |
|---|---|
| True positive | The detection correctly identified activity that matches the suspicious condition |
| False positive | The detection triggered on benign or expected activity |
| True negative | Benign activity was correctly not alerted |
| False negative | Malicious activity occurred but the detection failed to identify it |

A true-positive alert does not automatically mean a confirmed breach. It means the detection matched the activity it was designed to identify. The analyst still needs to establish what the activity means.

### Example

A rule alerts when an IP address generates more than ten failed logins.

- If a user repeatedly mistypes a password, the alert may be a false positive for malicious activity.
- If an unknown IP targets many accounts and one account is successfully accessed, the activity is more concerning and may indicate password spraying or account compromise.

## 5. A Practical SOC Investigation Workflow

Use a repeatable process. The exact steps depend on the alert type and the organisation's procedures.

### Step 1 – Understand the alert

Read the alert details:

- Alert name and description.
- Detection rule and threshold.
- Time of activity.
- Source and destination.
- Affected user or host.
- Severity and confidence assigned by the detection.

Do not rely only on the alert title. Review the underlying events.

### Step 2 – Identify the affected asset and identity

Determine:

- Hostname and IP address.
- Username and account type.
- Whether the account is privileged or a service account.
- Whether the device is a server, workstation, or critical asset.
- Whether the asset is expected to communicate with the observed source.

Asset criticality and account privilege can change the priority of an investigation.

### Step 3 – Examine the source and activity pattern

Check:

- Source IP address and whether it is internal or external.
- Number of attempts and time interval.
- Number of targeted accounts.
- Whether the source has appeared in previous alerts.
- Whether the activity matches normal behaviour.

IP reputation and geolocation can provide context, but neither proves that an IP is malicious. VPNs, proxies, shared networks, and inaccurate geolocation can affect interpretation.

### Step 4 – Check for successful authentication

Failed logins may be followed by a successful login. Look for related successful authentication events and compare:

- Username.
- Source IP.
- Hostname.
- Timestamp.
- Logon type.
- Authentication method, where available.

A successful login after failed attempts is a reason to investigate further, not proof by itself that the account was compromised.

### Step 5 – Review activity after authentication

If there is evidence of a suspicious successful login, inspect related activity, such as:

- New processes or unusual command execution.
- Privileged account use.
- New account creation.
- Group membership changes.
- Remote access or lateral movement.
- Security-tool tampering.
- Unusual outbound network connections.

Correlate records using reliable identifiers such as account, host, session, process, and time. Similar timestamps alone do not prove that two events are causally related.

### Step 6 – Determine scope and impact

Ask:

- Is one account or multiple accounts affected?
- Is one endpoint or multiple endpoints involved?
- Did the activity reach a critical server?
- Was privileged access obtained?
- Is there evidence of data access, modification, or exfiltration?
- Is the activity still ongoing?

Record what is confirmed, what is suspected, and what remains unknown.

### Step 7 – Classify, document, and escalate

Assign a classification and severity according to organisational policy. Record the supporting evidence and escalate to the appropriate team when required.

Do not make unsupported claims. Use wording such as:

- “The logs show…”
- “The activity is consistent with…”
- “This may indicate…”
- “No evidence was identified in the available logs…”
- “Further investigation is required to confirm…”

## 6. Investigating Windows Security Events in Splunk

The following searches are examples for a dataset where the relevant fields are extracted as `EventCode`, `TargetUserName`, `IpAddress`, `Computer`, `LogonType`, and `ProcessName`.

Your own data may use different field names or event formats. Check the actual fields in your events before using these searches. Replace `index=main` if your data is stored in another index.

### 6.1 Find failed logins – Event ID 4625

Windows Event ID 4625 records a failed logon attempt.

```spl
index=main EventCode=4625
| stats count as Failed_Attempts
        dc(TargetUserName) as Unique_Accounts
        values(TargetUserName) as Targeted_Accounts
        by IpAddress
| sort - Failed_Attempts
```

What this search does:

- Finds failed logon events.
- Counts failed attempts for each source IP.
- Counts distinct targeted accounts.
- Lists the targeted account names.
- Sorts the results by the highest number of failures.

A high number of failed attempts against many accounts may be consistent with password spraying. Validate the time pattern and other evidence before classifying it.

### 6.2 Review successful logins – Event ID 4624

Event ID 4624 records a successful logon.

```spl
index=main EventCode=4624
| table _time Computer TargetUserName IpAddress LogonType
| sort 0 _time
```

Review the source, account, host, logon type, and time. A successful login is not inherently suspicious; compare it with the user's normal activity and the surrounding events.

### 6.3 Investigate process creation – Event ID 4688

Event ID 4688 records process creation when the relevant auditing is enabled.

```spl
index=main EventCode=4688
| table _time Computer TargetUserName ProcessName
| sort 0 _time
```

Review unexpected processes and execution context. Process command-line details may require additional audit policy configuration and suitable event collection. The exact field names depend on the event format and parsing.

### 6.4 Find new user accounts – Event ID 4720

Event ID 4720 records a user account creation.

```spl
index=main EventCode=4720
| table _time Computer TargetUserName
| sort 0 _time
```

Check whether the account creation was authorised and whether it occurred during an expected change window. The event may contain separate fields for the account created and the account that performed the action.

### 6.5 Review privilege-related events

Examples of relevant Windows Security Event IDs include:

| Event ID | Description |
|---|---|
| 4672 | Special privileges assigned to a new logon |
| 4728 | Member added to a global security group |
| 4729 | Member removed from a global security group |
| 4732 | Member added to a local security group |
| 4733 | Member removed from a local security group |

Example search:

```spl
index=main (EventCode=4672 OR EventCode=4728 OR EventCode=4729 OR EventCode=4732 OR EventCode=4733)
| table _time Computer EventCode TargetUserName
| sort 0 _time
```

Inspect the raw events to identify the affected account, the actor, and the group involved. A field such as `TargetUserName` may not represent the same identity in every event type.

### 6.6 Build an investigation timeline

A timeline helps an analyst understand the order of recorded activity.

```spl
index=main (EventCode=4624 OR EventCode=4625 OR EventCode=4688 OR EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| sort 0 _time
| table _time Computer EventCode TargetUserName IpAddress ProcessName
```

This is a starting point, not a complete universal timeline. Some fields will be absent from particular event types. Add or adjust fields after reviewing the raw events and your data model.

**Important timeline cautions:**

- Confirm that event timestamps are parsed correctly.
- Check time zones and clock synchronisation.
- Use the correct account, host, session, or process identifiers when correlating events.
- A timeline shows recorded order; it does not automatically establish causation.
- Missing events may mean logging was not enabled, collection failed, or the activity was not recorded.

## 7. Containment, Eradication, and Recovery in Practice

### Containment

The goal is to stop the incident from spreading or causing more damage.

Examples:

- Isolate a compromised endpoint using the approved EDR process.
- Disable or temporarily restrict a compromised account with authorisation.
- Block confirmed malicious indicators through approved controls.
- Restrict affected network segments where necessary.

Containment decisions should consider business impact and preserve evidence where possible.

### Eradication

The goal is to remove the threat and its persistence.

Examples:

- Remove malicious files and unauthorised scheduled tasks.
- Remove unauthorised accounts or access mechanisms.
- Patch the exploited vulnerability.
- Reset compromised credentials and revoke affected sessions or tokens.
- Rebuild a system when its integrity cannot be trusted.

Simply deleting a suspicious file may not remove all persistence or resolve the initial weakness.

### Recovery

The goal is to return systems to a trusted operating state.

Examples:

- Restore from known-clean backups.
- Reinstall or rebuild affected systems where required.
- Validate security controls and system integrity.
- Restore services in a controlled order.
- Monitor for repeated suspicious activity.

Recovery is not complete until the organisation has checked that the threat has been addressed and systems are operating safely.

## 8. Evidence Collection and Preservation

Evidence is the information used to understand and support an investigation.

Examples include:

- Windows Event Logs and Linux system logs.
- SIEM alerts and search results.
- EDR investigation records.
- Firewall, DNS, proxy, and network logs.
- Relevant files and file hashes.
- Process, service, and persistence information.
- Screenshots and analyst notes, where permitted.

### Evidence-handling principles

1. Follow the organisation's evidence-handling policy.
2. Record who collected the evidence and when.
3. Record the system, source, and collection method.
4. Preserve original evidence and avoid unnecessary modification.
5. Use approved secure storage and access controls.
6. Record transfers and access to the evidence.
7. Use cryptographic hashes, such as SHA-256, when appropriate to help verify file integrity.

### Chain of custody

Chain of custody is the documented record of who handled evidence, when they handled it, and what they did with it.

It helps demonstrate that evidence was properly controlled and that its integrity was considered.

A basic record may contain:

| Field | Example |
|---|---|
| Evidence ID | EV-001 |
| Description | Exported Windows Security log |
| Source | WORKSTATION-01 |
| Collected by | Analyst name or ID |
| Date and time | Recorded with time zone |
| Collection method | Approved log export |
| SHA-256 | Calculated hash, if applicable |
| Storage location | Approved evidence repository |
| Transfer history | Person, time, and reason |

Do not collect, copy, or inspect data outside your authorisation or the organisation's procedures.

## 9. Common Incident Categories

| Incident type | Description | Example indicators |
|---|---|---|
| Phishing | Deceptive messages used to steal information or deliver malware | Suspicious email, link, attachment |
| Malware | Malicious software executes on a system | EDR detection, suspicious process |
| Ransomware | Malware encrypts or otherwise disrupts access to data | Mass file changes, ransom note |
| Brute force | Repeated password attempts against an account or service | Many failures against one account |
| Password spraying | A small number of common passwords tested against many accounts | One source targeting many users |
| Account compromise | An unauthorised person uses a legitimate account | Unusual login and account activity |
| Privilege escalation | An actor obtains higher permissions | Unexpected admin rights or privileged activity |
| Lateral movement | An actor moves between systems | Unusual remote logons or administrative access |
| Data exfiltration | Data is transferred out of an environment without authorisation | Unusual outbound transfer patterns |
| Insider threat | A trusted person misuses access, intentionally or unintentionally | Unusual access or policy violations |

These are investigation categories, not conclusions. Indicators must be validated against the available evidence.

## 10. Incident Severity and Priority

Organisations use severity levels to help decide how quickly an incident needs attention. The exact definitions differ between organisations.

| Level | General meaning | Example |
|---|---|---|
| Critical | Severe or widespread impact, or active compromise of critical systems | Confirmed ransomware on critical infrastructure |
| High | Significant risk or confirmed compromise requiring urgent response | Privileged account compromise |
| Medium | Suspicious activity with limited or uncertain impact | Repeated suspicious authentication attempts |
| Low | Limited impact or lower-risk policy/security event | Isolated low-confidence event |

Consider these factors when assessing severity:

- Business criticality of the affected asset.
- Privilege level of the account.
- Evidence of successful compromise.
- Scope and number of affected systems.
- Sensitivity of affected data.
- Whether the activity is ongoing.
- Confidence in the available evidence.

**Severity is not the same as confidence.** Severity estimates potential or actual impact; confidence describes how strongly the evidence supports the assessment.

## 11. Writing a Professional SOC Incident Report

A good incident report is factual, clear, chronological, and reproducible. It should allow another analyst or responder to understand what happened and what remains to be done.

### Recommended report structure

#### 1. Incident details

- Incident ID:
- Incident title:
- Date and time detected:
- Analyst:
- Severity:
- Status:

#### 2. Executive summary

Write a short summary of the alert, affected assets, and current assessment.

#### 3. Detection details

- Detection source:
- Alert name:
- Detection rule:
- Triggering condition:
- Relevant event IDs:

#### 4. Affected assets and identities

- Hostname:
- IP address:
- Username:
- Asset criticality:
- Other affected systems:

#### 5. Investigation timeline

| Time (include time zone) | Event | Evidence/source |
|---|---|---|
| 09:10 | Repeated failed logins observed | Windows Security logs |
| 09:14 | Successful login recorded | Windows Security logs |
| 09:18 | Analyst began endpoint review | SOC case notes |

The times above are illustrative only. Use actual evidence in a real report.

#### 6. Findings

Separate confirmed facts from hypotheses.

- Confirmed observations:
- Suspicious indicators:
- Evidence not available:
- Remaining questions:

#### 7. Impact and scope

Describe the affected accounts, systems, services, and data, and state what is not yet known.

#### 8. Response actions

Record containment, eradication, and recovery actions, including who authorised and performed them.

#### 9. Recommendations

List practical actions to reduce the chance or impact of recurrence.

#### 10. Current status

State whether the incident is open, under investigation, contained, recovering, or closed according to the organisation's workflow.

### Example of careful reporting language

**Weak statement:** “The attacker hacked the company server.”

**Better statement:** “The collected authentication logs show repeated failed logon attempts against the account, followed by a successful logon from the same recorded source IP. The available evidence warrants further investigation to determine whether the successful access was authorised.”

The second statement reports what the evidence supports without claiming more than is known.

## 12. Common Mistakes During Incident Investigation

- Closing an alert without reviewing the underlying events.
- Treating every failed login as an attack.
- Assuming a successful login means an account is compromised.
- Trusting IP reputation or geolocation as conclusive evidence.
- Ignoring the activity that occurred after authentication.
- Confusing event time with ingestion time.
- Assuming two events are related only because their timestamps are close.
- Failing to preserve relevant evidence.
- Taking disruptive response actions without authorisation.
- Writing conclusions that are not supported by evidence.
- Forgetting to record investigation steps and escalation decisions.

## 13. Important Windows Event IDs for SOC Investigation

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4647 | User-initiated logoff |
| 4648 | Logon attempted using explicit credentials |
| 4672 | Special privileges assigned to a new logon |
| 4688 | Process creation |
| 4697 | Service installed |
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset attempt |
| 4725 | User account disabled |
| 4726 | User account deleted |
| 4728 | Member added to a global security group |
| 4729 | Member removed from a global security group |
| 4732 | Member added to a local security group |
| 4733 | Member removed from a local security group |
| 4740 | User account locked out |
| 4768 | Kerberos authentication ticket (TGT) requested |
| 4769 | Kerberos service ticket requested |
| 4771 | Kerberos pre-authentication failed |
| 4776 | NTLM credential validation |

Event availability and detail depend on Windows version, audit policy, and collection configuration. Always inspect the raw event and verify the relevant fields.

## 14. SOC Interview Questions and Answers

### 1. What is incident response?

Incident response is the organised process of detecting, analysing, containing, eradicating, and recovering from security incidents, followed by reviewing the response and improving security.

### 2. What is the difference between an event, an alert, and an incident?

An event is a recorded activity. An alert is a notification generated by a detection. An incident is a security situation that requires investigation and response.

### 3. What are the four traditional phases in NIST SP 800-61 Revision 2?

Preparation; Detection and Analysis; Containment, Eradication and Recovery; and Post-Incident Activity.

### 4. What is alert triage?

Alert triage is the initial assessment of an alert to understand what triggered it, identify affected assets, review context, estimate risk, and decide whether to investigate, escalate, or close it.

### 5. What is the difference between containment and eradication?

Containment limits the impact or spread of an incident. Eradication removes the threat and its persistence from the environment.

### 6. What would you do if Splunk generated an alert for repeated failed logins?

I would review the triggering events, identify the source IP and targeted accounts, examine the attempt count and time pattern, check for successful logins, and review subsequent account and endpoint activity. I would document the evidence and escalate according to the incident-response procedure.

### 7. What is chain of custody?

It is the documented history of evidence collection, handling, access, and transfer. It helps demonstrate that evidence was controlled throughout the investigation.

### 8. Why is a timeline useful?

A timeline organises relevant activity chronologically and helps investigators understand the sequence of recorded events. Correlation identifiers and context are still needed to establish relationships between events.

### 9. What is the difference between severity and confidence?

Severity describes the potential or actual impact. Confidence describes how strongly the available evidence supports the finding.

### 10. What should an analyst do after identifying a compromised endpoint?

Follow the organisation's response procedure, preserve relevant evidence, and escalate. If authorised, the response team may isolate the endpoint, investigate the scope, remove the threat, restore the system, and monitor it.

### 11. Why should an analyst avoid unsupported conclusions?

Incident reports may be used by other technical teams, management, auditors, or investigators. Unsupported claims can mislead decision-makers and damage the reliability of the investigation.

### 12. What is a false negative?

A false negative occurs when malicious activity takes place but the detection system does not identify it.

## 15. Quick Revision Notes

- An **event** is recorded activity; an **alert** is a detection notification; an **incident** requires investigation and response.
- Alert triage is the initial assessment of a security alert.
- The traditional NIST SP 800-61 Rev. 2 lifecycle has four phases: Preparation; Detection and Analysis; Containment, Eradication and Recovery; Post-Incident Activity.
- **Containment** limits impact; **eradication** removes the threat; **recovery** restores trusted operations.
- Event ID **4625** = failed logon; **4624** = successful logon; **4688** = process creation; **4720** = account creation.
- A successful login after failures is suspicious context, not automatic proof of compromise.
- A timeline helps organise evidence, but timestamps alone do not prove causation.
- Chain of custody documents evidence handling.
- Severity and confidence are different measurements.
- Incident reports should distinguish confirmed facts from hypotheses.
- Follow organisational policy and obtain authorisation before disruptive response actions.

## 16. Useful References

- [NIST SP 800-61 Revision 2 – Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
- [NIST SP 800-61 Revision 3 – Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [Microsoft Learn – Windows Security Auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ About)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

**End of Day 08 – Incident Investigation and Response**
