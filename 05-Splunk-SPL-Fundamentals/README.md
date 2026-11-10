# Day 05 — Splunk Search Processing Language (SPL): Beginner to Advanced

> **Learning path:** SOC Analyst Foundations  
> **Level:** Beginner to intermediate, with an introduction to advanced SPL  
> **Dataset:** Synthetic Windows Security Events CSV (52 events)  
> **Purpose:** Learn how to search, filter, aggregate, investigate, and explain security events using Splunk.

---

## 1. What Is SPL?

**SPL (Search Processing Language)** is Splunk's search and analysis language. SOC analysts use it to search machine-generated data, filter events, extract fields, aggregate activity, correlate evidence, and build reports or dashboards.

Typical SOC questions answered with SPL include:

- How many failed logons occurred?
- Which accounts were targeted most often?
- Which source IP generated repeated authentication failures?
- Did a successful logon occur after repeated failures?
- Which accounts were created or added to privileged groups?
- Was PowerShell or another unusual process executed?

SPL helps analysts investigate large volumes of logs more efficiently than manually reading individual events.

## 2. Anatomy of an SPL Search and the Pipe Operator

An SPL search is a sequence of search terms and commands. The pipe character `|` passes the results of one command to the next.

```spl
index=main EventCode=4625
| stats count by TargetUserName
| sort - count
```

How it works:

1. `index=main EventCode=4625` selects failed-logon events in the main index.
2. `stats count by TargetUserName` counts events for each account.
3. `sort - count` sorts the largest counts first.

The pipeline is processed from left to right. Each command operates on the results produced by the preceding part of the search.

## 3. Indexes, Sources, Sourcetypes, Hosts, and Fields

These terms describe where data is stored and how Splunk identifies it.

| Term | Meaning |
|---|---|
| `index` | Logical location in Splunk where events are stored, such as `main` |
| `source` | Input from which an event was collected, such as a file |
| `sourcetype` | Classification of the event format, such as `csv` |
| `host` | Host metadata assigned to the event |
| Field | A named piece of information extracted from an event |

Common Splunk metadata fields:

- `_time`: timestamp Splunk uses for the event.
- `_raw`: original raw event text.
- `host`: host metadata assigned by Splunk.
- `source`: input source.
- `sourcetype`: event format classification.
- `index`: index containing the event.

**Important for the Day 05 CSV:** The upload host shown in Splunk (for example, `LAPTOP-7ACAMDT4`) is not necessarily the same as the CSV's `Computer` field. The CSV contains its own fields such as `TimeCreated`, `Computer`, `EventCode`, `TargetUserName`, and `IpAddress`.

## 4. Understanding Event Fields and Field Extraction

A field is a named value extracted from an event. For example:

```text
EventCode=4625
TargetUserName=administrator
IpAddress=203.0.113.50
Computer=WIN-CLIENT01
LogonType=10
Status=0xC000006D
```

Here, `EventCode`, `TargetUserName`, `IpAddress`, `Computer`, `LogonType`, and `Status` are fields.

Inspect events and their extracted fields:

```spl
index=main
| head 5
```

Summarize fields Splunk has discovered:

```spl
index=main
| fieldsummary
```

Display selected fields:

```spl
index=main
| table _time host Computer EventCode TargetUserName IpAddress
```

Field names must match the actual extracted names. Splunk field names are case-sensitive in normal use. For the supplied CSV, use `TargetUserName` and `IpAddress`, not `TargetUsername` or `_IpAddress`.

If a field is missing, inspect an expanded event and the field sidebar before assuming the data is absent. CSV field extraction can depend on the sourcetype and ingestion configuration.

## 5. Basic Search and Filtering

A basic search selects events using an index and field-value conditions.

Search all events in an index:

```spl
index=main
```

Search failed Windows logons:

```spl
index=main EventCode=4625
```

Search events for one account:

```spl
index=main TargetUserName=administrator
```

Combine conditions:

```spl
index=main EventCode=4625 TargetUserName=administrator
```

A search can also include metadata constraints, for example:

```spl
index=main sourcetype=csv host="LAPTOP-7ACAMDT4" EventCode=4625
```

Use constraints only when they match the data you are investigating. If a search unexpectedly returns zero events, remove constraints one at a time to identify which condition is excluding the events.

## 6. Essential Display and Result-Handling Commands

| Command | Purpose |
|---|---|
| `table` | Display selected fields in a table |
| `fields` | Keep or remove fields from the results |
| `sort` | Sort results |
| `head` | Return the first N results |
| `dedup` | Remove duplicate results based on fields |
| `rename` | Rename a field in the results |

Examples:

```spl
index=main EventCode=4625
| table _time TimeCreated Computer TargetUserName IpAddress Status
```

```spl
index=main
| fields _time host EventCode TargetUserName IpAddress
```

```spl
index=main
| fields - _raw
```

```spl
index=main
| sort - _time
```

```spl
index=main
| head 10
```

```spl
index=main EventCode=4625
| dedup TargetUserName
```

```spl
index=main EventCode=4625
| rename TargetUserName AS Username
| table Username IpAddress
```

**Remember:** `dedup` removes duplicate results; it does not count them. Use `stats count by field` when you need counts.

## 7. Boolean Operators, Parentheses, and Wildcards

Boolean logic narrows or broadens a search.

- `AND`: both conditions must match.
- `OR`: either condition can match.
- `NOT`: excludes matching conditions.
- Parentheses: group conditions and make the intended logic clear.

Examples:

```spl
index=main EventCode=4625 AND TargetUserName=administrator
```

```spl
index=main (EventCode=4624 OR EventCode=4625)
```

```spl
index=main EventCode=4625 NOT TargetUserName=svc_backup
```

The asterisk (`*`) is a wildcard for partial matching:

```spl
index=main TargetUserName=admin*
```

```spl
index=main ProcessName="*powershell.exe"
```

Wildcards are useful for searching partial usernames, process paths, filenames, and other string values. Be careful with broad wildcards because they may return many unrelated events.

## 8. Time-Based Searching and Event Time

SOC investigations are time-sensitive. An analyst often searches a defined period before and after an alert.

Common relative time modifiers:

| Modifier | Meaning |
|---|---|
| `earliest=-15m` | Last 15 minutes |
| `earliest=-1h` | Last hour |
| `earliest=-24h` | Last 24 hours |
| `earliest=-7d` | Last 7 days |
| `earliest=@d` | Start of the current day |
| `earliest=-24h latest=now` | Previous 24 hours through now |

Example:

```spl
index=main EventCode=4625 earliest=-24h
```

The Splunk time picker also affects the search. For the Day 05 training CSV, select **All time** while investigating the complete uploaded dataset.

**Event timestamp caution:** The CSV contains a `TimeCreated` field. If Splunk has not parsed it into `_time`, time-based charts may use the upload/indexing time instead of the timestamp inside the CSV. Parse it explicitly when needed:

```spl
index=main
| eval _time=strptime(TimeCreated,"%Y-%m-%d %H:%M:%S")
| timechart span=15m count
```

The timestamp format in `strptime` must match the actual CSV values.

## 9. The stats Command and Aggregation Functions

`stats` transforms matching events into summarized results. It is one of the most important SPL commands for SOC analysis.

Count all matching events:

```spl
index=main
| stats count
```

Count failed logons per username:

```spl
index=main EventCode=4625
| stats count by TargetUserName
```

Count failed logons per source IP:

```spl
index=main EventCode=4625
| stats count by IpAddress
```

Count by both IP and account:

```spl
index=main EventCode=4625
| stats count by IpAddress TargetUserName
```

Useful aggregation functions:

| Function | Meaning |
|---|---|
| `count` | Number of matching events |
| `dc(field)` | Number of distinct field values |
| `sum(field)` | Sum of numeric values |
| `avg(field)` | Average of numeric values |
| `min(field)` / `max(field)` | Minimum / maximum |
| `values(field)` | Distinct values collected into a multivalue result |
| `earliest(field)` / `latest(field)` | Earliest / latest field value |

Example: count failed logons and distinct accounts per IP:

```spl
index=main EventCode=4625
| stats count dc(TargetUserName) AS Unique_Users by IpAddress
| sort - count
```

Repeated failures against multiple accounts may be consistent with password spraying, but the pattern is only an investigative lead. Validate the timing, account context, source, and related events.

## 10. Filtering Aggregated Results with where

The `where` command filters results using expressions and comparisons. It is especially useful after aggregation.

```spl
index=main EventCode=4625
| stats count by IpAddress
| where count >= 5
```

This returns IP addresses with at least five matching failed-logon events.

Other examples:

```spl
index=main EventCode=4625
| stats count by IpAddress
| where count > 10
```

```spl
index=main EventCode=4625
| stats count by IpAddress
| where count >= 5 AND count <= 20
```

**Difference:** `search` is commonly used to find matching events and field values. `where` evaluates expressions against fields in the current result set and is often used after transforming commands such as `stats`.

## 11. Creating and Modifying Fields with eval

`eval` creates or modifies fields using expressions and functions.

Example: label failed logons:

```spl
index=main
| eval Event_Type=if(EventCode=4625,"Failed Login","Other Event")
| table EventCode Event_Type TargetUserName
```

Example: create a demonstration label for a known training IP:

```spl
index=main EventCode=4625
| eval Review_Label=if(IpAddress="203.0.113.50","Training IP - Review","Other")
| table TargetUserName IpAddress Review_Label
```

The label is not a threat-intelligence verdict. The dataset uses documentation IP space for training, so this value must not be treated as a real attacker address.

Other common uses of `eval` include string manipulation, mathematical calculations, conditional classification, and timestamp conversion.

## 12. Timechart, top, and rare

### timechart

`timechart` creates time-series results and is useful for identifying spikes or changes in activity.

```spl
index=main EventCode=4625
| timechart span=15m count
```

```spl
index=main EventCode=4625
| timechart span=5m count by IpAddress
```

### top

`top` displays the most frequent values:

```spl
index=main EventCode=4625
| top limit=10 TargetUserName
```

### rare

`rare` displays the least frequent values:

```spl
index=main
| rare limit=10 TargetUserName
```

A spike or rare value may deserve attention, but unusual frequency alone does not prove malicious activity. Consider normal baselines, system roles, maintenance windows, and business context.

## 13. Windows Security Event IDs Relevant to SOC Investigations

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Account logoff |
| 4648 | Logon attempted using explicit credentials |
| 4672 | Special privileges assigned to a new logon |
| 4688 | New process created |
| 4720 | User account created |
| 4728 | Member added to a security-enabled global group |
| 4729 | Member removed from a security-enabled global group |
| 4732 | Member added to a security-enabled local group |
| 4733 | Member removed from a security-enabled local group |
| 4740 | User account locked out |

Important context:

- Event ID 4624 means a logon succeeded; it does not automatically mean the activity was legitimate.
- Event ID 4625 means a logon failed; it does not automatically mean an attack occurred.
- Event ID 4688 records process creation. Command-line details require the relevant audit policy and command-line process creation logging to be configured.
- Group membership events should be investigated with the group name, affected member, actor, time, and change authorization.
- Event availability depends on Windows audit policy, log configuration, permissions, and retention.

Common Windows logon types:

| Logon Type | Meaning |
|---|---|
| 2 | Interactive (local console) |
| 3 | Network |
| 4 | Batch |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext |
| 9 | NewCredentials |
| 10 | RemoteInteractive (commonly RDP) |
| 11 | CachedInteractive |

Interpret logon types with the source, destination, user, and environment context.

## 14. Practical SOC Search Patterns for the Day 05 Dataset

The training dataset contains 52 synthetic Windows security events and fields such as `TimeCreated`, `Computer`, `EventCode`, `TargetUserName`, `IpAddress`, `LogonType`, `Status`, `ProcessName`, and `Message`.

Start by validating ingestion:

```spl
index=main
| stats count
```

If all records were indexed and the search time range includes them, the expected total is 52.

Event ID distribution:

```spl
index=main
| stats count by EventCode
| sort - count
```

Failed logons:

```spl
index=main EventCode=4625
| table TimeCreated Computer TargetUserName IpAddress Status
```

Successful logons:

```spl
index=main EventCode=4624
| table TimeCreated Computer TargetUserName IpAddress LogonType
```

New accounts:

```spl
index=main EventCode=4720
| table TimeCreated Computer TargetUserName
```

Group membership changes:

```spl
index=main (EventCode=4728 OR EventCode=4732)
| table TimeCreated Computer TargetUserName EventCode
```

PowerShell process events:

```spl
index=main EventCode=4688
| search ProcessName="*powershell.exe"
| table TimeCreated Computer TargetUserName ProcessName
```

The synthetic CSV may not contain every Windows event field normally available in a fully configured environment. For example, the actor account or group name may not be separately extracted in this simplified dataset.

## 15. Advanced SPL Command Overview

These commands extend SPL beyond basic searching and aggregation.

| Command | Purpose | Typical SOC use |
|---|---|---|
| `rex` | Extract fields using regular expressions | Extract IPs, domains, or usernames from raw text |
| `lookup` | Add data from a lookup table | Enrich events with asset or threat-intelligence context |
| `transaction` | Group related events into transactions | Examine related event sequences |
| `eventstats` | Calculate statistics and add them to each event | Compare individual events with group totals |
| `streamstats` | Calculate running or windowed statistics | Analyze sequences and changing event rates |
| `append` | Append results from another search | Combine result sets |
| `join` | Join results on common fields | Correlate datasets when appropriate |
| `fillnull` | Replace null values | Make missing values explicit |
| `coalesce` | Return the first non-null value | Handle alternate field names |
| `bin` | Group numeric or time values into buckets | Build time-based summaries |

These commands have different performance and semantic trade-offs. For large datasets, prefer efficient filtering and aggregation; do not use expensive commands such as `transaction` or broad joins without a clear reason.

## 16. Field Extraction with rex

`rex` uses regular expressions to extract values from a field, commonly `_raw`.

Example: extract an IPv4-looking string:

```spl
index=main
| rex field=_raw "(?<Extracted_IP>\d{1,3}(?:\.\d{1,3}){3})"
| table _raw Extracted_IP
```

The named capture group `(?<Extracted_IP>...)` creates a field named `Extracted_IP`.

This regular expression identifies an IPv4-shaped string; it does not validate that the address is a valid or routable IP address. Use appropriate validation and context for security decisions.

## 17. Enrichment and Correlation: lookup, eventstats, streamstats, and transaction

### lookup

A lookup enriches events with fields from a reference table. For example, an asset inventory could map hostnames to departments or criticality.

General pattern:

```spl
index=main
| lookup asset_inventory.csv Computer OUTPUT department criticality
```

The lookup file and field names must exist and be configured in Splunk before this search can work.

### eventstats

`eventstats` calculates aggregate values and adds them to the original events:

```spl
index=main EventCode=4625
| eventstats count AS Total_Failures by IpAddress
| table TimeCreated IpAddress TargetUserName Total_Failures
```

### streamstats

`streamstats` calculates running statistics over the ordered result stream:

```spl
index=main EventCode=4625
| sort 0 TimeCreated
| streamstats count AS Running_Failures by IpAddress
| table TimeCreated IpAddress TargetUserName Running_Failures
```

For reliable sequence analysis, ensure the events are sorted by the correct event timestamp. If `TimeCreated` is a string, parse it to a timestamp first.

### transaction

`transaction` groups events based on shared field values and time constraints. It can help examine a sequence of related events, but it can be resource-intensive on large datasets. Prefer `stats`, `streamstats`, or other efficient methods when they can answer the question.

## 18. Correlating Failed and Successful Logons

A SOC analyst should not investigate failed logons in isolation. A useful question is whether a successful authentication followed repeated failures from the same source or against the same account.

Search both event types:

```spl
index=main (EventCode=4624 OR EventCode=4625)
| sort 0 TimeCreated
| table TimeCreated EventCode TargetUserName IpAddress Status LogonType
```

Summarize successes and failures by IP:

```spl
index=main (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) AS Failed_Logons
        count(eval(EventCode=4624)) AS Successful_Logons
        by IpAddress
| sort - Failed_Logons
```

This provides a useful overview, but does not prove that a particular success followed a particular failure. For a stronger correlation, compare the same source IP, account, and event timestamps, and investigate the surrounding events.

For the training data, `203.0.113.50` is a documentation-range address used in the synthetic scenario. It is not evidence of a real external attacker.

## 19. Troubleshooting SPL Searches and Common Mistakes

When a search returns no results, troubleshoot methodically.

1. **Check the index:** Confirm the correct index, such as `index=main`.
2. **Check the time picker:** Use All time when examining the complete training dataset.
3. **Remove filters gradually:** Start with `index=main`, then add `EventCode=4625`, then add other constraints one at a time.
4. **Inspect raw events:** Use `index=main | head 5` and expand an event.
5. **Verify field names:** Use `fieldsummary` and check the CSV headers.
6. **Check field extraction:** Confirm the CSV sourcetype has extracted fields as expected.
7. **Check spelling and capitalization:** For example, use `TargetUserName` and `IpAddress` exactly as present in the dataset.
8. **Check quoting:** Use `EventCode=4624`, not the quoted literal string `"EventCode=4624"`.
9. **Distinguish metadata from CSV fields:** `host` is Splunk metadata; `Computer` is a CSV field.
10. **Check timestamps:** `TimeCreated` may need parsing into `_time` for time charts.

Useful diagnostic searches:

```spl
index=main
| stats count
```

```spl
index=main
| head 5
```

```spl
index=main
| fieldsummary
```

```spl
index=main
| stats count by EventCode
```

A frequent mistake is using an incorrect field name in `table`. For example, `_IpAddress` is not the same as `IpAddress`, and `TargetUsername` is not the same as `TargetUserName`.

## 20. SOC Investigation Scenarios, SPL Answers, and Interview Revision

The following scenarios demonstrate how an analyst translates an investigation question into a search and interprets its output. These are examples for the synthetic Day 05 dataset; always base conclusions on the actual search results.

### Scenario A — Find repeated failed logons

**Question:** Which source IP addresses generated five or more failed logon events?

```spl
index=main EventCode=4625
| stats count by IpAddress
| where count >= 5
| sort - count
```

**Interpretation:** A source with many failures may indicate brute-force attempts, password spraying, a misconfigured service, or legitimate user error. Review time distribution, targeted accounts, and surrounding events.

### Scenario B — Identify the most targeted accounts

**Question:** Which usernames received the most failed logon attempts?

```spl
index=main EventCode=4625
| stats count by TargetUserName
| sort - count
```

**Interpretation:** Repeated failures against privileged or service accounts deserve careful review. Confirm whether the activity is expected and whether any successful logon followed.

### Scenario C — Find IPs targeting multiple accounts

**Question:** Which IP addresses attempted to authenticate against multiple different usernames?

```spl
index=main EventCode=4625
| stats count dc(TargetUserName) AS Unique_Users by IpAddress
| where Unique_Users > 1
| sort - Unique_Users
```

**Interpretation:** One source attempting many accounts may be consistent with password spraying or account enumeration. It is not conclusive without additional evidence.

### Scenario D — Review successful logons

**Question:** Which accounts successfully logged on, and from which IP addresses?

```spl
index=main EventCode=4624
| table TimeCreated Computer TargetUserName IpAddress LogonType
```

**Interpretation:** Review unusual source addresses, logon types, times, and account privilege. A successful logon is not automatically malicious or benign.

### Scenario E — Look for success and failure activity from the same IP

**Question:** Which IPs have both failed and successful logons?

```spl
index=main (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) AS Failures
        count(eval(EventCode=4624)) AS Successes
        by IpAddress
| where Failures > 0 AND Successes > 0
```

**Interpretation:** This identifies IPs with both event types in the search period. Inspect event timestamps and usernames to determine whether the successful event is related to the failures.

### Scenario F — Detect newly created accounts

**Question:** Which user accounts were created?

```spl
index=main EventCode=4720
| table TimeCreated Computer TargetUserName
```

**Interpretation:** Confirm the account creation was approved. In a full Windows event, examine the actor who created the account and additional account attributes.

### Scenario G — Review privileged group membership changes

**Question:** Which events indicate a member was added to a security-enabled group?

```spl
index=main (EventCode=4728 OR EventCode=4732)
| table TimeCreated Computer EventCode TargetUserName
```

**Interpretation:** Check the affected group, member, initiating account, and change authorization. The training CSV may not expose all of those fields.

### Scenario H — Find PowerShell process creation events

**Question:** Which process creation events contain PowerShell?

```spl
index=main EventCode=4688
| search ProcessName="*powershell.exe"
| table TimeCreated Computer TargetUserName ProcessName
```

**Interpretation:** PowerShell is a legitimate administration tool and is also used by attackers. Review command-line arguments, parent process, user context, script content, and related network activity when available.

### Scenario I — Count events over time

**Question:** When did failed logon activity increase?

```spl
index=main EventCode=4625
| eval _time=strptime(TimeCreated,"%Y-%m-%d %H:%M:%S")
| timechart span=15m count
```

**Interpretation:** A sudden increase can be a useful lead. Confirm the timestamp format and compare with normal activity before concluding that an attack occurred.

### Scenario J — Summarize authentication activity by source

**Question:** Show failed and successful logon totals for each source IP.

```spl
index=main (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) AS Failed
        count(eval(EventCode=4624)) AS Successful
        dc(TargetUserName) AS Distinct_Accounts
        by IpAddress
| sort - Failed
```

**Interpretation:** This summary helps prioritize sources for further investigation. It is a starting point, not a complete incident determination.

### Common SOC interview questions

**Q1. What is SPL?**  
SPL is Splunk's Search Processing Language, used to search, filter, analyze, aggregate, and visualize machine-generated data.

**Q2. What does the pipe operator do?**  
It passes the results of one SPL command to the next command in the search pipeline.

**Q3. What is the difference between stats and eventstats?**  
`stats` returns aggregated results. `eventstats` calculates aggregate values and adds them to the existing events.

**Q4. What is the difference between table and fields?**  
`table` displays selected fields in a tabular result. `fields` keeps or removes fields from the result set.

**Q5. What is the difference between dedup and stats count by?**  
`dedup` removes duplicate results based on selected fields. `stats count by` calculates the number of events for each field value.

**Q6. How would you investigate brute-force activity?**  
Search failed logons (4625), group by source IP and username, identify repeated attempts, review time patterns, and correlate with successful logons (4624). Validate the account, source, and surrounding activity before escalating.

**Q7. What is a lookup?**  
A lookup enriches search results with reference data such as asset inventory, department, device criticality, or approved threat-intelligence context.

**Q8. What is timechart used for?**  
It creates time-based statistical results to help identify spikes, trends, and changes in activity.

**Q9. Does a failed logon prove an attack?**  
No. Failed logons can result from mistyped passwords, expired credentials, misconfigured services, or malicious activity. Context and correlation are required.

**Q10. Does a successful logon prove an account was compromised?**  
No. A successful logon is an event to investigate in context, particularly if it follows suspicious failures or originates from an unusual source.

---

## Quick SPL Reference

| Requirement | SPL pattern |
|---|---|
| Search an index | `index=main` |
| Failed logons | `EventCode=4625` |
| Successful logons | `EventCode=4624` |
| Count events | `stats count` |
| Count by username | `stats count by TargetUserName` |
| Count by IP | `stats count by IpAddress` |
| Sort descending | `sort - count` |
| Display fields | `table field1 field2` |
| Remove duplicates | `dedup field` |
| Filter a calculated result | `where count >= 5` |
| Create a field | `eval NewField=...` |
| Chart over time | `timechart span=15m count` |
| Most frequent values | `top field` |
| Least frequent values | `rare field` |
| Extract using regex | `rex` |
| Enrich using reference data | `lookup` |

## Dataset and Investigation Notes

- The Day 05 CSV is synthetic training data, not a real company log export.
- It contains 52 sample Windows security events.
- The IP address `203.0.113.50` belongs to documentation address space and is used as a training example, not as a real attacker indicator.
- The expected event count is 52 if all records were indexed and the search time range includes them.
- CSV field extraction and timestamp parsing depend on the Splunk upload configuration.
- Do not claim an incident solely from a threshold or one event. Correlate evidence, validate context, document findings, and escalate according to procedure.

## Official Documentation

- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Search Tutorial](https://docs.splunk.com/Documentation/Splunk/latest/SearchTutorial/Startsearching)
- [SPL Command Quick Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Commands)
- [Splunk Search Manual](https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutthesearchlanguage)

---

**Day 05 takeaway:** A SOC analyst uses SPL to move from raw events to evidence: search the right data, verify fields and timestamps, aggregate activity, identify suspicious patterns, correlate related events, and explain what the evidence does and does not prove.
