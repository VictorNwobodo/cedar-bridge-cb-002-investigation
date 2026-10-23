# Week 2 Investigation Report

**Case:** CB-002  
**Programme:** VAM Cohort 4  
**Due date:** 18 October 2026, 23:59 WAT

**Learner name:** [Enter your full name]

**Analysis route:** Wireshark

# 1. Scope

This investigation reviews fictional training evidence provided for Case CB-002. The purpose is to examine authentication activity, network traffic, and a suspicious email to determine whether the available evidence requires further investigation.

The following evidence was reviewed:

- **E01:** Fictional email received on 12 October 2026.
- **Windows authentication records W01–W07:** Selected-field export containing successful and failed logon events.
- **Linux authentication records L01–L04:** SSH authentication records from CB-LINUX-01.
- **Network packet reference:** Frames 1–13 from the supplied training capture, `week2-traffic.pcap`.
- **A01:** Training SIEM alert triggered by repeated failed Windows logons followed by a successful logon.

The network capture was examined using Wireshark. Display filters were used to inspect traffic involving CB-LT-07, DNS queries, and HTTP requests.

The Windows export and packet timestamps use UTC. Linux log timestamps include the `+01:00` time-zone offset, which is West Africa Time (WAT). All timestamps in the timeline are normalized to WAT for comparison, while original timestamps and zones are retained in the authentication evidence table.

**Limitations**

The Windows CSV is a simplified export, not a complete Windows Event Log file. The supplied packet capture is a small generated training capture. Its TLS application-data record cannot be decrypted using the available evidence because no TLS keys were supplied.

Full email transport headers, SPF/DKIM/DMARC results, endpoint process records, VPN/NAT mapping, complete server logs, DNS reputation results, and user confirmation were not provided.

The investigation is limited to inspecting and preserving the supplied evidence, documenting findings, and recommending further checks to a supervisor. I have not blocked addresses, disabled accounts, or performed unauthorized containment.

# 2. Authentication Evidence

## 2.1 Windows and Linux authentication records

The following table summarizes the relevant authentication events.

| Record ID | Original timestamp and zone | WAT timestamp | Host | Account | Source IP | Action | Outcome |
|---|---|---|---|---|---|---|---|
| W01 | 2026-10-12 08:00:00 UTC | 09:00:00 | CB-FILE-01 | ben | 10.20.0.25 | Network logon, Event ID 4624 | Success |
| W02 | 2026-10-12 08:11:00 UTC | 09:11:00 | CB-FILE-01 | ben | 10.20.0.25 | Network logon, Event ID 4625 | Failure |
| W03 | 2026-10-12 08:11:20 UTC | 09:11:20 | CB-FILE-01 | ben | 10.20.0.25 | Network logon, Event ID 4624 | Success |
| W04 | 2026-10-12 08:12:00 UTC | 09:12:00 | CB-FILE-01 | amara | 198.51.100.77 | Network logon, Event ID 4625 | Failure |
| W05 | 2026-10-12 08:12:20 UTC | 09:12:20 | CB-FILE-01 | amara | 198.51.100.77 | Network logon, Event ID 4625 | Failure |
| W06 | 2026-10-12 08:12:40 UTC | 09:12:40 | CB-FILE-01 | amara | 198.51.100.77 | Network logon, Event ID 4625 | Failure |
| W07 | 2026-10-12 08:13:10 UTC | 09:13:10 | CB-FILE-01 | amara | 198.51.100.77 | Network logon, Event ID 4624 | Success |
| L01 | 2026-10-12 09:12:05 +01:00 | 09:12:05 | CB-LINUX-01 | amara | 198.51.100.77 | SSH password authentication | Failure |
| L02 | 2026-10-12 09:12:25 +01:00 | 09:12:25 | CB-LINUX-01 | amara | 198.51.100.77 | SSH password authentication | Failure |
| L03 | 2026-10-12 09:13:20 +01:00 | 09:13:20 | CB-LINUX-01 | amara | 198.51.100.77 | SSH password authentication | Success |
| L04 | 2026-10-12 09:20:00 +01:00 | 09:20:00 | CB-LINUX-01 | admin | 10.20.0.10 | SSH public-key authentication | Success |

**Interpretation of the event IDs:** Windows Event ID 4625 indicates a failed logon, while Event ID 4624 indicates a successful logon. Logon type 3 represents a network logon and does not prove that an interactive desktop session was opened.

## 2.2 Search conditions and counts

For the Windows search, I filtered the exported records using these conditions:

- Account: `amara`
- Source IP: `198.51.100.77`
- Host: `CB-FILE-01`
- Date: 12 October 2026
- Time range: 08:12:00–08:13:10 UTC, inclusive

The matching records were W04, W05, W06, and W07.

**Results:**
- Failed Windows logons: 3 (W04–W06).
- Successful Windows logons: 1 (W07).
- Linux authentication failures: 2 (L01–L02).
- Successful Linux SSH authentication: 1 (L03).
- Training SIEM alert: A01.

A01 was generated because three failed Windows logons for the same account and source were followed by a successful logon within the rule's specified time window.

The alert is a signal for investigation, not an additional authentication event. It must not be counted as another login.

Ben's records W02–W03 show one failed logon followed by a successful logon. This may be routine activity, but its context has not been independently confirmed.

# 3. Timeline

The following timeline places the relevant email, authentication events, and network observations in chronological order using WAT.

| WAT timestamp | Evidence ID | Observation |
|---|---|---|
| 09:05:00 | E01 | Email received. It requests that Amara enter her account password within ten minutes to avoid suspension of access. |
| 09:12:00 | W04 | Failed Windows network logon for Amara from 198.51.100.77. |
| 09:12:05 | L01 | Failed SSH password authentication for Amara from 198.51.100.77. |
| 09:12:20 | W05 | Second failed Windows network logon for Amara from the same source. |
| 09:12:25 | L02 | Second failed SSH password authentication for Amara from the same source. |
| 09:12:40 | W06 | Third failed Windows network logon for Amara from the same source. |
| 09:13:10 | W07 | Successful Windows network logon for Amara from 198.51.100.77. |
| 09:13:20 | L03 | Successful SSH password authentication for Amara from the same source. |
| 09:14:00 | Frame 3 | CB-LT-07 queries DNS for `billing-review.example`. |
| 09:14:01 | Frame 4 | DNS response returns `198.51.100.80`. |
| 09:15:05 | Frame 8 | CB-LT-07 sends an HTTP GET request to `/review` with Host `billing-review.example`. |
| 09:15:06 | Frame 9 | The remote server returns HTTP 200 OK. The supplied observation identifies the response body as a training page only. |
| 09:16:03 | Frame 13 | CB-LT-07 sends synthetic TLS application data to the approved portal's IP address, `192.0.2.80`, over port 443. |

**Timeline interpretation**

The email was received before the authentication events. The observed HTTP request occurred after the recorded Windows and Linux authentication successes.

This ordering establishes a temporal relationship but does not establish causation. The available evidence does not prove that Amara clicked the email link, that the email caused the authentication activity, or that the same person or process generated all these events.

The packet capture identifies CB-LT-07 as the observed network device. It does not independently identify the human user responsible for the traffic.

# 4. Network Figures

Three annotated Wireshark screenshots will be inserted in this section.

## Figure 1: Traffic involving CB-LT-07

**Required display filter:** `ip.addr == 10.20.0.24`

**Insert screenshot here:**

[ATTACH SCREENSHOT 1: Wireshark capture showing the filter `ip.addr == 10.20.0.24` and relevant packets.]

**Caption:** Figure 1. Wireshark display-filter results for traffic to or from CB-LT-07 (10.20.0.24). The filter displays packets where this IP address appears as either the source or destination. Relevant DNS, HTTP, and HTTPS traffic is included in the supplied training capture.

**Annotation checklist:**
- Ensure the display-filter bar is visible.
- Ensure relevant frame numbers are visible.
- Show the UTC date-and-time display format.
- Highlight the DNS query and HTTP request where possible.

## Figure 2: DNS traffic

**Required display filter:** `dns`

**Insert screenshot here:**

[ATTACH SCREENSHOT 2: Wireshark DNS-filter results showing frames 3 and 4.]

**Caption:** Figure 2. DNS traffic showing the query for `billing-review.example` in frame 3 and the response containing `198.51.100.80` in frame 4. The observed resolution establishes which address was returned in this capture but does not establish whether the domain is malicious.

**Annotation checklist:**
- Ensure the `dns` display filter is visible.
- Highlight frame 3 and the queried domain.
- Highlight frame 4 and the returned IP address.
- Keep the relevant timestamps visible.

## Figure 3: HTTP request

**Required display filter:** `http.request`

**Insert screenshot here:**

[ATTACH SCREENSHOT 3: Wireshark HTTP request showing frame 8.]

**Caption:** Figure 3. HTTP request in frame 8 at 08:15:05 UTC (09:15:05 WAT). The request uses Host `billing-review.example` and the path `/review`. Frame 9 records an HTTP 200 OK response.

**Annotation checklist:**
- Ensure the `http.request` display filter is visible.
- Select frame 8.
- Expand the Hypertext Transfer Protocol details.
- Highlight the Host field and request URI.
- Keep the UTC timestamp visible.

**Screenshot integrity note:** These figures should be genuine screenshots from the supplied training capture. The screenshots should document the analysis without exposing unrelated private information.

# 5. Network Findings

## 5.1 DNS observations

Frame 3 records a DNS query from CB-LT-07 (10.20.0.24) to the office DNS resolver (10.20.0.53) for:

`billing-review.example`

Frame 4 records the DNS response, returning:

`198.51.100.80`

This domain and address are not listed among the supplied approved domains and addresses.

The observations establish that the device queried the domain and received the specified DNS response. They do not independently establish the domain's reputation, ownership, or intent.

## 5.2 HTTP observations

Frames 5–7 show a TCP connection being established between CB-LT-07 and `198.51.100.80` on destination port 80.

Frame 8 records this HTTP request:

- **Host:** `billing-review.example`
- **Request path:** `/review`
- **Time:** 08:15:05 UTC
- **Equivalent WAT:** 09:15:05

Frame 9 records an HTTP 200 OK response, described in the supplied reference as containing a training page only.

These records establish that an HTTP request was observed and a successful HTTP response was recorded. They do not establish that the user entered a password, submitted credentials, or downloaded a malicious file.

## 5.3 HTTPS and encrypted content

Frames 10–13 show a TCP connection between CB-LT-07 and `192.0.2.80` over destination port 443.

Frame 13 contains a synthetic TLS application-data record. No TLS decryption keys were supplied, and the record does not contain a readable HTTP body in the provided reference.

The available evidence does not establish the content of that encrypted application data. It also does not establish that a password was submitted or stolen.

In a typical encrypted HTTPS session, network observers may still see connection metadata such as IP addresses, ports, packet sizes, and timing. Application content generally requires suitable decryption material to inspect. Some metadata visibility depends on the protocols and configurations in use.

## 5.4 Supported observations, hypotheses, and missing evidence

**Supported observations**
- CB-LT-07 queried `billing-review.example` and received `198.51.100.80` in response.
- CB-LT-07 sent an HTTP GET request to `/review`.
- The server returned HTTP 200 OK.
- A separate TLS application-data record was observed to the approved portal's IP address.

**Hypotheses requiring investigation**
- The unlisted domain may be related to the email's request for billing-access confirmation.
- The email and network traffic may be associated with the same activity.

These are hypotheses, not established findings.

**Missing evidence**
- Browser history and endpoint process/session telemetry.
- User confirmation obtained through an approved channel.
- DNS reputation and domain-registration context.
- Complete proxy, firewall, and network logs.
- TLS decryption material, if available and authorized.
- Evidence showing whether any credentials were entered or transmitted.

# 6. Email Review

**Evidence ID:** E01  
**Received:** 12 October 2026, 08:05:00 UTC (09:05:00 WAT)

| Field | Observed value |
|---|---|
| Display name | Cedar Bridge IT |
| Sender | helpdesk@billing-review.example |
| Reply-To | review@billing-review.example |
| Recipient | amara@cedarbridge.example |
| Subject | Confirm your billing access in ten minutes |
| Actual link destination | `hxxp://billing-review[.]example/review` |
| Normalized destination domain | `billing-review.example` |
| Requested action | Enter the account password to prevent access suspension |
| Attachment | None |

## 6.1 Concerning features

The email displays the name Cedar Bridge IT, but the sender uses `billing-review.example` rather than the supplied approved portal domain, `portal.cedarbridge.example`.

The message also uses urgency by imposing a ten-minute deadline and threatens access suspension. It asks the recipient to enter an account password through a link.

The sender and Reply-To addresses both use the same unlisted domain. This does not prove that the email is malicious, but the combination of an unlisted destination, urgency, and a password request warrants independent verification.

The visible link text, “Open the staff portal,” does not match the actual destination's approved status. The supplied instructions prohibit opening the link, so it was treated as evidence and not followed.

## 6.2 Missing email-authentication evidence

The full transport headers and SPF, DKIM, and DMARC results were not supplied.

Consequently, this review cannot establish whether the sending infrastructure passed email-authentication checks or whether the message was authorized by the legitimate organization.

The email's display name alone cannot establish the sender's identity.

## 6.3 Recommended email checks

Request the complete message headers and available SPF/DKIM/DMARC results. Confirm through an independently obtained, approved contact method whether Cedar Bridge IT sent the email.

If available and authorized, review email gateway logs and endpoint/browser records to determine whether the link was accessed and what activity followed.

# 7. Hypothetical Malware Evidence Requests

The following scenarios are general evidence-request examples. They are not claims that these activities occurred in Case CB-002.

## Scenario A: Unexplained encrypted files

**Evidence to request**
- File inventory, paths, timestamps, hashes, and file-change records.
- Endpoint detection logs and process execution history around the time the files changed.
- Relevant file-server audit logs and access records.
- Backup status, backup timestamps, and recovery-test results.
- Related DNS, proxy, and network connection records.

**Questions these records help answer**

These records can help determine which files changed, whether a process was responsible, whether the changes were consistent with expected activity, and whether recoverable backups exist.

The evidence may help distinguish authorized encryption or application activity from suspicious file modification. Encrypted files alone do not prove ransomware.

## Scenario B: Suspected browser credential theft

**Evidence to request**
- Endpoint security alerts and process execution telemetry.
- Browser security and relevant browser activity records, collected with appropriate authorization.
- Account sign-in history and session records.
- MFA events and authentication-risk alerts.
- Relevant DNS, proxy, and network logs.
- Available evidence of credential-access activity or unauthorized session use.

**Questions these records help answer**

These records can help determine whether a process accessed browser-related data, whether suspicious authentication activity followed, and whether an account or session may have been compromised.

A successful login alone does not establish credential theft. Correlation between endpoint, browser, and account records is needed.

## Scenario C: A downloaded programme starting child processes

**Evidence to request**
- Parent-child process trees and process creation events.
- Executable paths, hashes, command lines, and digital-signature information.
- File download and browser history records, where authorized.
- Endpoint security detections and quarantine records.
- Related DNS, proxy, firewall, and network connection logs.

**Questions these records help answer**

These records can help identify the downloaded programme, determine which child processes it created, inspect their command-line arguments, and establish whether they made network connections.

The process tree and related network records can help distinguish expected application behaviour from suspicious execution. A parent process creating child processes is not, by itself, proof of malware.

# 8. Recommendation

## Decision: Investigate further

The available evidence warrants further investigation. Closing the case as harmless would be premature, but declaring a confirmed breach would exceed what the supplied records establish.

### Supporting evidence

1. **E01:** The email requests a password under a ten-minute deadline and directs the recipient to the unlisted domain `billing-review.example`.
2. **W04–W07:** Three failed Windows logons for Amara from `198.51.100.77` are followed by a successful logon.
3. **L01–L03:** Two failed SSH password attempts are followed by successful SSH password authentication for Amara from the same source IP.
4. **Frames 3–4:** CB-LT-07 resolves `billing-review.example` to `198.51.100.80`.
5. **Frame 8:** CB-LT-07 sends an HTTP GET request to `/review` on the unlisted domain.
6. **Frame 9:** The server returns HTTP 200 OK.

Together, these records establish several observations that merit correlation and verification. They do not establish that the email caused the authentication activity or that the account was compromised.

### Plausible benign alternative

The authentication attempts could have resulted from a legitimate remote-access session involving mistyped passwords, an approved connection, or another authorized activity.

The email and subsequent HTTP request may be related, but the available records do not establish who initiated the traffic or whether the email link was clicked.

### Unanswered questions

- Was the source IP associated with an approved VPN, NAT gateway, or other authorized connection?
- Did Amara confirm the activity through an approved verification channel?
- Was MFA required and successfully completed for the relevant sessions?
- Which endpoint process and user session generated the observed HTTP request?
- Were any credentials entered or transmitted?
- Do full email headers and authentication results support the claimed sender identity?
- Is there additional DNS, proxy, endpoint, or server evidence that changes the assessment?

### Next authorized action

I recommend preserving the supplied logs, packet capture, and email sample in their original form, recording evidence IDs and timestamps, and requesting further investigation through the designated supervisor.

The supervisor or appropriately authorized incident-response personnel should approve any containment action, such as disabling an account or blocking a destination, if subsequent evidence justifies it.

I would not independently disable accounts, block addresses, or declare a confirmed compromise based on the current evidence.

**Final assessment:** Case CB-002 requires further investigation. The supplied evidence supports concern about the email, authentication sequence, and network request, but the cause, user intent, and impact remain unverified.

# 9. Submission Check

Before submission, confirm that:

- [ ] My full name is entered.
- [ ] The analysis route is identified as Wireshark.
- [ ] The authentication table contains original timestamps, zones, normalized WAT times, hosts, accounts, source IPs, actions, and outcomes.
- [ ] The timeline includes E01, W04–W07, L01–L03, and network frames 3, 8, and 13.
- [ ] Three genuine annotated Wireshark screenshots have been inserted into Section 4.
- [ ] The screenshots show their display filters, relevant frame numbers, and timestamp view.
- [ ] The email review distinguishes observed facts from hypotheses and identifies missing authentication evidence.
- [ ] The three hypothetical malware scenarios are presented as evidence-request examples, not as events that occurred in CB-002.
- [ ] The recommendation includes supporting evidence, a benign alternative, unanswered questions, and the next authorized action.
- [ ] The report is saved as one viewable document.
- [ ] The document link is submitted under **Veenode Learn → Your work & marks → Week 2 investigation report**.
- [ ] The ten scored checks for each Veenode Labs lab are submitted separately.
