# Day 06 — Advanced SPL for SOC Analysts

> **Learning path:** SOC Analyst Foundations  
> **Level:** Intermediate to advanced  
> **Focus:** Field extraction, enrichment, event correlation, sequence analysis, and threat hunting  
> **Prerequisites:** Day 05 — Splunk SPL Fundamentals  
> **Practice environment:** Splunk Enterprise or Splunk Free with suitable sample security logs

---

## 1. Learning Objectives

By the end of this lesson, you should understand how to:

- Extract useful fields from unstructured and structured events.
- Use regular expressions with `rex`.
- Extract JSON fields with `spath`.
- Enrich events with reference data using `lookup`.
- Add aggregate context to events with `eventstats`.
- Calculate running statistics with `streamstats`.
- Group related events with `transaction`.
- Use subsearches to pass results between searches.
- Combine search results using `append` and `join`.
- Group timestamps into intervals with `bin`.
- Correlate authentication and endpoint events to investigate suspicious behaviour.
- Explain what a search result demonstrates—and what it does not prove.

## 2. Why Advanced SPL Matters in a SOC

A single security event rarely explains an entire incident. An analyst may see:

1. Several failed authentication attempts.
2. A successful logon to the same account.
3. A suspicious process starting on the endpoint.
4. A new account being created.
5. A change to a privileged security group.

Each event needs context. Advanced SPL helps an analyst extract fields, summarize patterns, compare events, and investigate whether multiple observations may be related.

**Core investigation principle:** Correlation creates an investigative lead; it does not automatically prove causation or compromise. Validate the user, host, source, timestamps, and surrounding evidence.

## 3. Field Extraction: Structured and Unstructured Data

A field is a named value extracted from an event. Some data sources provide structured fields automatically, while others store useful details inside a raw message.

Example raw event:

```text
Failed login for administrator from 192.168.1.50
```

Potential fields include:

- `Username`: administrator
- `Source_IP`: 192.168.1.50

Field extraction makes data easier to search, filter, aggregate, and correlate.

Before extracting fields, inspect actual events:

```spl
index=main
| head 5
```

Use the Events view to expand an event and inspect `_raw` and the extracted fields. Do not assume that every dataset uses the same field names.

## 4. Regular Expressions (Regex) Fundamentals

A regular expression is a pattern used to match text. Splunk's `rex` command uses regular expressions to extract values from event fields.

| Pattern | Meaning |
|---|---|
| `\\d` | A digit |
| `\\w` | A word character |
| `\\s` | Whitespace |
| `+` | One or more repetitions |
| `*` | Zero or more repetitions |
| `.` | Any character (except newline in common regex modes) |
| `{n}` | Exactly n repetitions |
| `{n,m}` | Between n and m repetitions |
| `[abc]` | One character from the set |
| `^` | Beginning of a string/line |
| `$` | End of a string/line |
| `(...)` | Capturing group |
| `(?<FieldName>...)` | Named capture group |

Example pattern for an IPv4-shaped string:

```regex
\\d{1,3}(?:\\.\\d{1,3}){3}
```

This identifies a string with four dot-separated groups of one to three digits. It does not validate that each octet is between 0 and 255, nor does it establish that the address is routable or malicious.

## 5. Extracting Fields with rex

The `rex` command extracts fields using a regular expression. It is commonly applied to `_raw` or another text field.

Example raw message:

```text
Failed login for administrator from 192.168.1.50
```

Search:

```spl
index=main
| rex field=_raw "Failed login for (?<Username>\\w+) from (?<Source_IP>\\d{1,3}(?:\\.\\d{1,3}){3})"
| table Username Source_IP
```

Explanation:

- `rex`: performs regular-expression extraction.
- `field=_raw`: tells Splunk which field to inspect.
- `(?<Username>...)`: creates a field named `Username`.
- `(?<Source_IP>...)`: creates a field named `Source_IP`.

Extract an email address:

```spl
index=main
| rex field=_raw "(?<Email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,})"
| table Email
```

Extract a value from a message formatted as `user=alice`:

```spl
index=main
| rex field=_raw "user=(?<Username>\\w+)"
| table Username
```

**SOC uses:** Extracting usernames, IP addresses, domains, URLs, process names, and other indicators from unstructured application, firewall, proxy, and authentication messages.

## 6. Extracting JSON Fields with spath

Many modern products and services generate JSON events. JSON stores information as key-value pairs and nested objects.

Example:

```json
{
  "timestamp": "2026-11-19T10:30:00Z",
  "user": "administrator",
  "source_ip": "192.168.1.50",
  "event": "failed_login",
  "status": "failure"
}
```

If the JSON is in the raw event, use `spath` to extract its fields:

```spl
index=main
| spath
| table user source_ip event status
```

Extract specific JSON paths into named fields:

```spl
index=main
| spath input=_raw path=user output=Username
| spath input=_raw path=source_ip output=Source_IP
| table Username Source_IP
```

For nested JSON, specify the path to the required value. For example, a value inside an object named `actor` may use a path such as `actor.name`.

**Difference between rex and spath:**

| `rex` | `spath` |
|---|---|
| Uses regular-expression patterns | Parses structured JSON/XML-style data |
| Useful for unstructured text | Useful for structured data |
| Analyst defines the matching pattern | Analyst specifies or uses structured paths |

Use `spath` when the data is genuinely structured JSON. Use `rex` when you need pattern-based extraction from text.

## 7. Data Enrichment with lookup

A security event may contain an IP address or hostname but not explain which department owns the asset or how critical it is.

A lookup adds context from a reference dataset, such as:

| IpAddress | Hostname | Department | Criticality |
|---|---|---|---|
| 192.168.1.50 | HR-PC01 | HR | Medium |
| 192.168.1.60 | FIN-PC01 | Finance | High |
| 192.168.1.70 | SOC-PC01 | Security | High |

Example:

```spl
index=main
| lookup asset_inventory.csv IpAddress OUTPUT Hostname Department Criticality
| table IpAddress Hostname Department Criticality
```

Here:

- `asset_inventory.csv` is a lookup file configured in Splunk.
- `IpAddress` is the matching field.
- `OUTPUT` lists fields to add to the search results.

The lookup must exist and be configured in Splunk before the search can use it.

Common SOC enrichment sources:

- Asset inventories and configuration management databases.
- User and identity directories.
- Approved network ranges.
- Vulnerability management data.
- Threat-intelligence reference lists.
- Business unit and asset criticality information.

**Caution:** A threat-intelligence match is a lead, not proof. Validate source quality, freshness, context, and the observed behaviour. Geo-IP is approximate and should not be treated as exact physical location.

## 8. eventstats: Add Aggregate Context to Events

The `stats` command aggregates events and returns a summary. The `eventstats` command calculates aggregate values and adds them to the existing events.

Using `stats`:

```spl
index=main EventCode=4625
| stats count by IpAddress
```

This returns a summary row for each IP address.

Using `eventstats`:

```spl
index=main EventCode=4625
| eventstats count AS Total_Failures by IpAddress
| table _time IpAddress TargetUserName Total_Failures
```

The total failure count is added to each matching event for that IP.

| Command | Result |
|---|---|
| `stats` | Aggregated result set |
| `eventstats` | Original events with aggregate fields added |

**SOC use:** Retain event-level details while displaying totals, averages, or other group-level context alongside each event.

## 9. streamstats: Running and Windowed Statistics

The `streamstats` command calculates running statistics over the search result stream. It can help analysts understand how a count changes as events are processed.

Example:

```spl
index=main EventCode=4625
| sort 0 _time
| streamstats count AS Running_Failures by IpAddress
| table _time IpAddress TargetUserName Running_Failures
```

For each IP address, the running count increases as matching events are processed.

A running count per account:

```spl
index=main EventCode=4625
| sort 0 _time
| streamstats count AS Running_Failures by TargetUserName
| table _time TargetUserName Running_Failures
```

Important considerations:

- Sort by the correct event timestamp before sequence analysis.
- Confirm that Splunk's `_time` represents the event time, not merely ingestion time.
- If the source timestamp is stored in a string field, parse it before sorting.
- A running count over the full search is not automatically a rolling time-window detector.
- Use a suitable `window` or time-based design when the detection requirement calls for a bounded window.

**SOC use:** Observe repeated authentication failures, running event totals, and changing activity patterns.

## 10. transaction: Group Related Events

The `transaction` command groups events that share specified fields and satisfy time constraints.

Example:

```spl
index=main (EventCode=4624 OR EventCode=4625)
| transaction TargetUserName maxspan=10m
| table TargetUserName eventcount duration
```

Important transaction fields include:

- `eventcount`: number of events in the transaction.
- `duration`: time span between the first and last event in the transaction.

The example groups events by username within a maximum span of ten minutes. Grouping only by username may combine events from different hosts or IP addresses. Where appropriate, include additional identifiers such as source IP or host.

Considerations:

- `transaction` can be memory- and resource-intensive.
- Broad searches can create large numbers of transactions.
- Incorrect grouping fields can combine unrelated events.
- Time constraints and event ordering matter.
- For many large-scale analytics tasks, `stats` or `streamstats` is more efficient.

**SOC use:** Examine related event sequences, such as authentication activity, when the grouping fields and time boundaries are well defined.

## 11. Subsearches: Use One Search to Inform Another

A subsearch is a search nested inside another SPL search. Its results are used to construct or constrain the outer search.

Example: find successful logons from IP addresses that also generated failed logons.

```spl
index=main EventCode=4624
[
    search index=main EventCode=4625
    | dedup IpAddress
    | fields IpAddress
]
```

How it works:

1. The inner search finds IP addresses associated with failed logons.
2. `dedup IpAddress` removes duplicate IP values.
3. `fields IpAddress` returns the field used by the outer search.
4. The outer search finds successful logons matching those IP addresses.

This identifies successful logons from sources that also generated failures in the searched data. It does not by itself prove that a particular success followed a particular failure. Compare timestamps and usernames for stronger correlation.

Subsearch limitations:

- Subsearches have default runtime and result limits.
- Large subsearch results may be truncated.
- The generated search can become complex.
- Validate the subsearch output and consider alternatives for large datasets.

## 12. append: Add One Result Set to Another

The `append` command adds the results of a secondary search to the current results.

Example: append a summary of successful logons to a summary of failed logons.

```spl
index=main EventCode=4625
| stats count AS Event_Count by TargetUserName
| append [
    search index=main EventCode=4624
    | stats count AS Event_Count by TargetUserName
]
```

This produces a combined result set with rows from both searches.

Important: `append` stacks result rows; it does not automatically match failed and successful counts into a single row per username. If you want one row per account with separate success and failure columns, conditional aggregation is usually simpler:

```spl
index=main (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) AS Failed_Logins
        count(eval(EventCode=4624)) AS Successful_Logins
        by TargetUserName
```

## 13. join: Combine Results Using a Common Field

The `join` command combines results from two searches using a shared field.

Example: combine failed and successful logon counts for usernames present in both searches.

```spl
index=main EventCode=4625
| stats count AS Failed_Logins by TargetUserName
| join type=inner TargetUserName [
    search index=main EventCode=4624
    | stats count AS Successful_Logins by TargetUserName
]
```

Key terms:

- `join`: combines results.
- `type=inner`: keeps records that match in both result sets.
- `TargetUserName`: common matching field.
- `Failed_Logins` and `Successful_Logins`: summary fields from the two searches.

Considerations:

- `join` has limits and can be expensive.
- Duplicate keys can complicate results.
- The field values must match in format and meaning.
- A join on username alone does not establish that events came from the same source or occurred in a particular sequence.

For many SOC summaries, conditional `stats` aggregation is faster and easier to maintain than `join`.

## 14. bin: Group Events into Time Buckets

The `bin` command groups continuous time or numeric values into intervals.

Example:

```spl
index=main EventCode=4625
| bin _time span=15m
| stats count by _time
```

This groups failed logons into fifteen-minute buckets.

Example interpretation:

| Time interval | Failed logons |
|---|---:|
| 10:00–10:15 | 2 |
| 10:15–10:30 | 4 |
| 10:30–10:45 | 25 |
| 10:45–11:00 | 3 |

The increase in one interval may be worth investigating. Compare with the normal baseline and related events before deciding whether it represents an attack.

`bin` is also known as `bucket` in Splunk SPL.

## 15. Correlating Failed and Successful Authentication Events

A useful SOC investigation asks whether an account or source IP generated both failed and successful logons.

Summary by IP and account:

```spl
index=main (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) AS Failed_Logins
        count(eval(EventCode=4624)) AS Successful_Logins
        by IpAddress TargetUserName
| where Failed_Logins > 0 AND Successful_Logins > 0
```

Review the event timeline:

```spl
index=main (EventCode=4624 OR EventCode=4625)
| sort 0 _time
| table _time EventCode TargetUserName IpAddress Status LogonType
```

Investigation questions:

- Did the failed attempts and successful logon involve the same account?
- Did they originate from the same IP?
- Did the success occur after the failures?
- Was the logon type expected?
- Was the account privileged or a service account?
- Were there related endpoint or network events?

**Interpretation:** Both event types from the same source/account may deserve investigation. They do not automatically establish account compromise.

## 16. Threat Hunting Scenario: Possible Password Spraying

Password spraying involves attempting a small number of passwords against many accounts, rather than trying many passwords against one account.

Identify IPs associated with failures against multiple accounts:

```spl
index=main EventCode=4625
| stats count dc(TargetUserName) AS Unique_Accounts by IpAddress
| where Unique_Accounts >= 3
| sort - Unique_Accounts
```

Review account-level activity:

```spl
index=main EventCode=4625
| stats count by IpAddress TargetUserName
| sort - count
```

Check successful logons:

```spl
index=main EventCode=4624
| stats count by IpAddress TargetUserName
```

Review the combined timeline:

```spl
index=main (EventCode=4624 OR EventCode=4625)
| sort 0 _time
| table _time EventCode TargetUserName IpAddress
```

Interpretation:

- One IP attempting multiple accounts may be consistent with password spraying.
- A high failure count against one account may be consistent with brute force.
- Successful authentication from the same source deserves further review.
- Confirm timestamps, source context, account ownership, and endpoint activity.

A threshold such as three accounts is a configurable example, not a universal detection rule.

## 17. Threat Hunting Scenario: Possible Unauthorized Privilege Change

Relevant Windows Security Event IDs:

| Event ID | Meaning |
|---|---|
| 4720 | User account created |
| 4728 | Member added to a security-enabled global group |
| 4729 | Member removed from a security-enabled global group |
| 4732 | Member added to a security-enabled local group |
| 4733 | Member removed from a security-enabled local group |

Search for account creation and group membership changes:

```spl
index=main (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| sort 0 _time
| table _time Computer EventCode TargetUserName
```

Investigate:

1. Which account was created or modified?
2. Which group was changed?
3. Which account initiated the change?
4. Was the change approved?
5. Did the activity occur during an expected maintenance window?
6. Were there related logons or process events?

The exact fields available depend on the Windows event data collected. A simplified CSV may not contain the actor account or group name as separate fields.

## 18. Threat Hunting Scenario: Suspicious PowerShell Process Activity

Windows Event ID 4688 indicates a new process was created.

Search for PowerShell process creation:

```spl
index=main EventCode=4688
| search ProcessName="*powershell.exe"
| table _time Computer TargetUserName ProcessName
```

In a more complete endpoint dataset, useful fields may include:

- Process command line.
- Parent process name and ID.
- Process ID.
- User or security principal.
- Hostname.
- Related network connections.

Investigative questions:

- Was PowerShell launched by an expected parent process?
- Was the user authorized to perform the activity?
- Were encoded or unusual command-line arguments present?
- Did the process access unusual files or make unexpected network connections?
- Was the activity part of normal administration?

PowerShell is a legitimate administration tool as well as a tool that attackers may abuse. Process execution alone is not proof of malicious activity. Command-line logging depends on the endpoint's audit configuration.

## 19. Common Advanced SPL Mistakes and Troubleshooting

| Mistake | Why it matters | Better approach |
|---|---|---|
| Using `transaction` on a broad search | Can consume significant resources | Filter early; consider `stats` or `streamstats` |
| Not sorting before sequence analysis | Running counts may not reflect event chronology | Sort by the correct event timestamp |
| Grouping only by username | May combine unrelated hosts or IPs | Include appropriate identity and source fields |
| Using `join` unnecessarily | Can be expensive and limited | Consider conditional aggregation with `stats` |
| Assuming all fields exist | Dataset schemas differ | Inspect events and use `fieldsummary` |
| Treating a running count as a rolling window | A cumulative count has different meaning | Configure an appropriate window or time-based condition |
| Ignoring timestamp parsing | Event order and charts may be wrong | Validate and parse the source timestamp |
| Treating a match as proof of compromise | One signal lacks full context | Correlate and validate independent evidence |

Useful diagnostic searches:

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
| stats count by sourcetype host
```

When a field is missing or a search returns no events, begin with the broad index search and add filters one at a time.

## 20. Interview Questions, Quick Reference, and Key Takeaways

### Interview questions

**Q1. What is the purpose of `rex`?**  
It extracts fields from event text using regular expressions.

**Q2. What is the difference between `rex` and `spath`?**  
`rex` uses regular-expression patterns to extract values from text. `spath` extracts values from structured JSON/XML-style data.

**Q3. What is the difference between `stats` and `eventstats`?**  
`stats` returns aggregated results. `eventstats` adds aggregate values to the existing events.

**Q4. What is `streamstats` used for?**  
It calculates running or windowed statistics over the result stream.

**Q5. What is a subsearch?**  
A search nested inside another search. Its results can be used to filter or influence the outer search.

**Q6. What is the difference between `append` and `join`?**  
`append` stacks one result set beneath another. `join` combines results using a common field.

**Q7. What is `lookup` used for?**  
It enriches search results with reference information, such as asset ownership, department, or approved intelligence data.

**Q8. Why should analysts be careful with `transaction`?**  
It can be resource-intensive and may group unrelated events if the grouping fields and time constraints are not appropriate.

**Q9. What is password spraying?**  
An attack technique that tries a small number of passwords against many user accounts.

**Q10. How would you investigate failed and successful logons?**  
I would search for Event IDs 4625 and 4624, group events by source IP and account, compare timestamps, review logon types, and correlate the activity with endpoint and identity events.

### Advanced SPL quick reference

| Requirement | Command or pattern |
|---|---|
| Extract fields with regex | `rex` |
| Extract JSON fields | `spath` |
| Enrich with reference data | `lookup` |
| Add aggregate values to events | `eventstats` |
| Calculate running statistics | `streamstats` |
| Group related events | `transaction` |
| Use one search inside another | Subsearch `[ search ... ]` |
| Append result sets | `append` |
| Join on common fields | `join` |
| Group time into intervals | `bin` |
| Summarize by time | `timechart` |
| Aggregate conditional counts | `stats count(eval(condition))` |

### Key takeaways

- Inspect the data and confirm field names before writing complex searches.
- Use `rex` for pattern-based extraction and `spath` for structured JSON.
- Use `lookup` to add asset, identity, or other reference context.
- Understand the difference between summary statistics and event-level context.
- Sort by reliable event timestamps before sequence analysis.
- Use `transaction`, `join`, and subsearches carefully because they have performance or result limits.
- Correlate authentication, identity, and endpoint events to develop an evidence-based timeline.
- A detection or threshold is an investigative lead, not proof of compromise.

### Official Splunk documentation

- [SPL Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [rex command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rex)
- [spath command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Spath)
- [lookup command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Lookup)
- [eventstats command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eventstats)
- [streamstats command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Streamstats)
- [transaction command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Transaction)
- [Splunk Search Manual](https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutthesearchlanguage)

---

**Day 06 takeaway:** Advanced SPL helps a SOC analyst turn separate log records into useful investigative context. Extract the right fields, enrich the data, summarize patterns, examine event sequences, correlate evidence, and document conclusions without overstating what the logs prove.
