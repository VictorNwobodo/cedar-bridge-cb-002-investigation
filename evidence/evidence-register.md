# Evidence Register — CB-002

| Evidence ID | Evidence type | Supplied content | Use in analysis | Limitation |
|---|---|---|---|---|
| W01 | Windows authentication | 08:00:00 UTC; CB-FILE-01; ben; 10.20.0.25; Event ID 4624 | Baseline successful logon | Context not independently confirmed |
| W02 | Windows authentication | 08:11:00 UTC; CB-FILE-01; ben; 10.20.0.25; Event ID 4625 | Failed logon followed by W03 | Context not independently confirmed |
| W03 | Windows authentication | 08:11:20 UTC; CB-FILE-01; ben; 10.20.0.25; Event ID 4624 | Ben's observed sequence | Context not independently confirmed |
| W04 | Windows authentication | 08:12:00 UTC; CB-FILE-01; amara; 198.51.100.77; Event ID 4625 | Authentication sequence | Simplified CSV, not full event log |
| W05 | Windows authentication | 08:12:20 UTC; same host/account/source; Event ID 4625 | Authentication sequence | Simplified CSV, not full event log |
| W06 | Windows authentication | 08:12:40 UTC; same host/account/source; Event ID 4625 | Authentication sequence | Simplified CSV, not full event log |
| W07 | Windows authentication | 08:13:10 UTC; same host/account/source; Event ID 4624 | Authentication sequence | Authorization/context not established |
| L01 | Linux SSH log | 09:12:05+01:00; CB-LINUX-01; amara; 198.51.100.77; failed password | Cross-host correlation | Full log bundle not included |
| L02 | Linux SSH log | 09:12:25+01:00; same host/account/source; failed password | Cross-host correlation | Full log bundle not included |
| L03 | Linux SSH log | 09:13:20+01:00; same host/account/source; accepted password | Cross-host correlation | Authorization/context not established |
| L04 | Linux SSH log | 09:20:00+01:00; CB-LINUX-01; admin; 10.20.0.10; accepted public key | Separate administrative event | Link to suspicious sequence not established |
| A01 | Detection alert | Triggered by three failed Windows logons followed by a success within rule window | Alert validation | Signal for investigation, not an extra login or proof of compromise |
| E01 | Email | Received 08:05:00 UTC; display name Cedar Bridge IT; helpdesk@billing-review.example; Reply-To review@billing-review.example; recipient amara@cedarbridge.example; subject requests billing access confirmation within ten minutes; password request; no attachment | Phishing assessment | Full transport headers and SPF/DKIM/DMARC results not supplied |
| Frames 3–4 | Packet references | 08:14:00 and 08:14:01 UTC; CB-LT-07 (10.20.0.24) queries billing-review.example via resolver 10.20.0.53; response returns 198.51.100.80 | DNS sequence | Packet details from supplied training reference |
| Frames 5–7 | Packet references | TCP connection from CB-LT-07 to 198.51.100.80 on port 80 | Connection context for HTTP | Full packet bytes not reproduced here |
| Frame 8 | Packet reference | 08:15:05 UTC; HTTP GET /review; Host billing-review.example | Web request | No form submission evidence supplied |
| Frame 9 | Packet reference | 08:15:06 UTC; HTTP 200 OK; response body described as training page only | HTTP response | Does not prove credential submission or malware |
| Frames 10–13 | Packet references | TCP connection from CB-LT-07 to 192.0.2.80 over port 443; frame 13 at 08:16:03 UTC shows synthetic TLS application data | Encrypted traffic observation | No decryption keys/content supplied |

Times ending in UTC/Z are UTC. WAT is UTC+1. The table summarizes supplied synthetic evidence; it does not claim original source files are archived in this repository.
