# Evidence Register — CB-002

| Evidence ID | Evidence type | Supplied content | Use in analysis | Limitation |
|---|---|---|---|---|
| W04 | Windows authentication | 08:12:00Z; CB-FILE-01; amara; 198.51.100.77; type 3; failed | Authentication sequence | Full raw event XML not included |
| W05 | Windows authentication | 08:12:20Z; same host/account/source/type; failed | Authentication sequence | Full raw event XML not included |
| W06 | Windows authentication | 08:12:40Z; same host/account/source/type; failed | Authentication sequence | Full raw event XML not included |
| W07 | Windows authentication | 08:13:10Z; same host/account/source/type; success | Authentication sequence | Authorization/context not established |
| L01 | Linux SSH log | 09:12:05+01:00; CB-LINUX-01; amara; 198.51.100.77; failed password | Cross-host correlation | Full log bundle not included |
| L02 | Linux SSH log | 09:12:25+01:00; same host/account/source; failed password | Cross-host correlation | Full log bundle not included |
| L03 | Linux SSH log | 09:13:20+01:00; same host/account/source; accepted password | Cross-host correlation | Authorization/context not established |
| L04 | Linux SSH log | 09:20:00+01:00; CB-LINUX-01; admin; 10.20.0.10; accepted public key | Separate administrative event | Link to suspicious sequence not established |
| A01 | Detection alert | 08:13:11Z; amara; CB-FILE-01; 198.51.100.77; matched W04–W07 | Alert validation | Alert is not independent proof of compromise |
| E01 | Email | From helpdesk@billing-review.example; Reply-To review@billing-review.example; to amara@cedarbridge.example; received 08:05:00Z; password request and urgency | Phishing assessment | Recipient interaction not established |
| Frames 3–4 | Packet references | DNS observation for billing-review.example to 198.51.100.80 at 08:15:00Z and 08:15:01Z | DNS sequence | Packet bytes unavailable |
| Frame 8 | Packet reference | HTTP GET /review; Host billing-review.example at 08:15:05Z | Web request | No form submission evidence supplied |
| Frame 9 | Packet reference | HTTP 200 response at 08:15:06Z | HTTP response | Response content not supplied |
| Frame 13 | Packet reference | TLS application data at 08:16:03Z | Encrypted traffic observation | No decryption keys/content supplied |

Times with Z are UTC. WAT is UTC+1. The table records the supplied evidence summary; it does not claim the original source files are archived in this repository.
