# Week 2 Investigation Report — CB-002

**Case date:** 12 October 2026  
**Analyst route:** Wireshark with supplied packet-reference evidence  
**Timezone normalization:** WAT (UTC+1)  
**Classification:** Fictional training case; findings limited to supplied evidence

## 1. Executive summary

The supplied records show three failed Windows network logons for the account `amara` on `CB-FILE-01`, followed by a successful logon from the same source IP, `198.51.100.77`. A Windows alert, A01, matched this sequence. Separate Linux SSH records show two failed password attempts for `amara` followed by a successful password authentication from the same source address on `CB-LINUX-01`.

A suspicious email, E01, urged the recipient to enter an account password within ten minutes and linked to `hxxp://billing-review[.]example/review`. Supplied packet references show DNS resolution for `billing-review.example`, an HTTP request to `/review`, an HTTP 200 response, and a later TLS application-data observation. These facts make the activity suspicious and justify preserving evidence and checking account/session activity.

**The evidence does not establish who controlled 198.51.100.77, prove that the recipient submitted credentials, demonstrate malware execution, or by itself prove unauthorized access or data loss.** The successful authentications are observations, not conclusive proof of compromise.

## 2. Scope and method

Reviewed the supplied synthetic evidence records W04–W07, L01–L04, E01, alert A01, and packet frames 3, 4, 8, 9, and 13. The packet-analysis route used Wireshark and the supplied packet-reference table.

The analysis:
- preserved original timestamps and timezone information;
- normalized timestamps to WAT (UTC+1);
- correlated authentication events by account, source IP, host, action, and proximity in time;
- separated directly observed activity from possible explanations; and
- identified follow-up evidence required before making an attribution or compromise determination.

### Limitations
The report does not include a full packet capture, complete Windows/Linux event exports, email gateway trace, endpoint process tree, identity-provider/session records, or evidence of what the recipient did after viewing the email. The original screenshot files were not available during publication. The packet-reference descriptions cannot substitute for full packet bytes or endpoint telemetry.

## 3. Authentication evidence

| Record | Original timestamp | WAT timestamp | Host | Account | Source IP | Action | Outcome |
|---|---|---|---|---|---|---|---|
| W04 | 2026-10-12 08:12:00Z | 2026-10-12 09:12:00 | CB-FILE-01 | amara | 198.51.100.77 | Windows network logon, type 3 | Failed |
| W05 | 2026-10-12 08:12:20Z | 2026-10-12 09:12:20 | CB-FILE-01 | amara | 198.51.100.77 | Windows network logon, type 3 | Failed |
| W06 | 2026-10-12 08:12:40Z | 2026-10-12 09:12:40 | CB-FILE-01 | amara | 198.51.100.77 | Windows network logon, type 3 | Failed |
| W07 | 2026-10-12 08:13:10Z | 2026-10-12 09:13:10 | CB-FILE-01 | amara | 198.51.100.77 | Windows network logon, type 3 | Success |
| L01 | 2026-10-12 09:12:05+01:00 | 2026-10-12 09:12:05 | CB-LINUX-01 | amara | 198.51.100.77 | SSH password authentication | Failed |
| L02 | 2026-10-12 09:12:25+01:00 | 2026-10-12 09:12:25 | CB-LINUX-01 | amara | 198.51.100.77 | SSH password authentication | Failed |
| L03 | 2026-10-12 09:13:20+01:00 | 2026-10-12 09:13:20 | CB-LINUX-01 | amara | 198.51.100.77 | SSH password authentication | Success |
| L04 | 2026-10-12 09:20:00+01:00 | 2026-10-12 09:20:00 | CB-LINUX-01 | admin | 10.20.0.10 | SSH public-key authentication | Success |

L01 and L02 record failed SSH password attempts for `amara` from `198.51.100.77`; L03 records a successful password authentication from that same source. L04 is a separate successful public-key login for `admin` from internal address `10.20.0.10`. The supplied evidence does not establish that L04 is connected to the suspicious activity.

## 4. Network observations

The packet references support the following limited observations:

| Frame | Original timestamp (UTC) | WAT | Observation | What it supports / does not support |
|---|---|---|---|---|
| 3 | 2026-10-12 08:15:00Z | 09:15:00 | DNS observation associated with `billing-review.example`, resolving to `198.51.100.80` | Supports a DNS lookup/resolution in the supplied trace; not proof of a malicious payload |
| 4 | 2026-10-12 08:15:01Z | 09:15:01 | Related DNS response/observation for the same domain and address | Corroborates the supplied DNS sequence |
| 8 | 2026-10-12 08:15:05Z | 09:15:05 | HTTP GET request for `/review`; Host: `billing-review.example` | Supports an HTTP request to the referenced host/path |
| 9 | 2026-10-12 08:15:06Z | 09:15:06 | HTTP 200 response | Shows a successful HTTP response; does not prove credential submission or successful authentication |
| 13 | 2026-10-12 08:16:03Z | 09:16:03 | TLS application-data traffic observed | Encrypted content cannot be determined from the supplied description; no TLS decryption keys or decrypted payload were provided |

### Wireshark filters and screenshot placements

The original working notes specify these screenshots:
- **Figure 1 — Host traffic:** filter `ip.addr == 10.20.0.24`
- **Figure 2 — DNS evidence:** filter `dns`, showing frames 3 and 4
- **Figure 3 — HTTP request:** filter `http.request`, showing frame 8, Host `billing-review.example`, URI `/review`

The genuine image files were not present in the publishing context, so they have not been fabricated or embedded. Add the original screenshots under `figures/` and link them here if available.

## 5. Email review — E01

| Field | Supplied evidence |
|---|---|
| Received | 2026-10-12 08:05:00Z (09:05:00 WAT) |
| From | `helpdesk@billing-review.example` |
| Reply-To | `review@billing-review.example` |
| To | `amara@cedarbridge.example` |
| Subject | “Confirm your billing access in ten minutes” |
| Body excerpt | “Your access will be suspended. Open the link below and enter your account password to keep your access.” |
| Link (defanged) | `hxxp://billing-review[.]example/review` |

The urgency, password request, and link to a billing-review domain are phishing indicators. The supplied evidence does not show whether the recipient clicked the link, entered credentials, downloaded a file, or submitted any form. Do not visit the link as part of this analysis.

## 6. Alert review — A01

A01 was generated at `2026-10-12T08:13:11Z` (09:13:11 WAT). It identified account `amara`, source `198.51.100.77`, and host `CB-FILE-01`, matching W04–W07: three failed Windows network logons followed by one success within the rule window.

The alert is consistent with the supplied records. It should be treated as a useful detection, not as independent proof that the successful logon was unauthorized.

## 7. Joined timeline

See [timeline.csv](../analysis/timeline.csv) for a sortable normalized timeline. The high-level sequence is:
1. 09:05 WAT — E01 received.
2. 09:12–09:13 WAT — failed Windows logons followed by a Windows success; Linux SSH failures and then a successful password authentication occur in the same short period.
3. 09:13:11 WAT — A01 generated from the Windows authentication pattern.
4. 09:15 WAT — supplied packet references show DNS activity for `billing-review.example`.
5. 09:15:05–09:15:06 WAT — HTTP GET `/review` and HTTP 200 response.
6. 09:16:03 WAT — TLS application-data traffic observed.

The temporal proximity is suspicious, but the supplied records alone do not prove that E01 caused the authentication events or that the same actor generated every event. The Windows and Linux authentication records use the same source IP, but source IP alone is not identity attribution.

## 8. Assessment and recommended actions

### Assessment
- **Confidence that suspicious authentication activity occurred:** High, within the supplied synthetic records.
- **Confidence that E01 has phishing characteristics:** High, based on urgency, a password request, and the link/domain.
- **Confidence that the recipient submitted credentials or that an attacker controlled the successful sessions:** Undetermined from supplied evidence.
- **Confirmed compromise or data loss:** Not established.

### Recommended authorized next steps
1. Preserve the original email with full headers and gateway delivery/URL-rewrite logs.
2. Preserve complete Windows Security logs from CB-FILE-01 and SSH/authentication logs from CB-LINUX-01 around the event window.
3. Check identity-provider, VPN, endpoint, and session records for the source IP and account; confirm whether the sign-ins match the user's known activity.
4. Ask the account owner whether they received or interacted with E01, without assuming they did.
5. Review subsequent file access, privilege changes, and session activity for `amara`.
6. If the incident lead finds evidence of unauthorized access, follow the approved incident process for session revocation, credential reset, and containment.
7. Retain the packet capture and original screenshots with hashes and chain-of-custody notes if available.

## 9. Conclusion

The joined evidence warrants escalation for validation because it combines a credential-seeking email, a suspicious HTTP visit, and closely timed failed-then-successful authentication on Windows and Linux. The defensible conclusion is **suspicious activity requiring further investigation**, not confirmed compromise. Additional identity, endpoint, and complete log evidence is necessary to determine whether credentials were exposed, who controlled the sessions, and whether any resources were accessed without authorization.
