# Cedar Bridge Case Study — CB-002
## Authentication Activity and Suspicious Billing-Link Review

This repository contains a junior-analyst investigation using **fictional, synthetic training evidence**. It joins Windows authentication records, Linux SSH logs, a suspicious email, and selected packet-capture observations. It is a learning artifact, not a claim about a real organization or real incident.

### Report
- [Week 2 investigation report](report/week-2-investigation-report.md)
- [Normalized timeline (WAT)](analysis/timeline.csv)
- [Findings and limitations](analysis/findings-and-limitations.md)
- [Evidence register](evidence/evidence-register.md)
- [Disclaimer](DISCLAIMER.md)

### Case snapshot
- **Case:** CB-002
- **Evidence date:** 12 October 2026
- **Analyst route:** Wireshark, using the supplied packet-reference evidence
- **Primary account:** amara
- **Primary Windows host:** CB-FILE-01
- **Linux host:** CB-LINUX-01
- **Observed source:** 198.51.100.77
- **Assessment:** Suspicious authentication activity warrants investigation. The supplied evidence does not independently establish who controlled the source address or prove a successful compromise.

### Evidence handling
All times are shown with the original timestamp and zone where known and normalized to West Africa Time (WAT, UTC+1). Packet evidence is interpreted only to the extent supported by the supplied records. No live destinations were visited, and no attachment or payload was executed.

### Screenshots
<img width="1919" height="1029" alt="ip-address" src="https://github.com/user-attachments/assets/811e3e9c-fe63-454e-90ea-c6bdabdd667c" />
<img width="1919" height="1031" alt="dns" src="https://github.com/user-attachments/assets/c72c2adf-d6b2-448e-9674-c0154f170afe" />
<img width="1919" height="1029" alt="http-request-frame8" src="https://github.com/user-attachments/assets/1b39719f-df2b-41ec-87c7-d9ae751f4e2b" />

The original working notes specify three Wireshark screenshots:
1. `ip.addr == 10.20.0.24`
2. `dns` showing frames 3 and 4
3. `http.request` showing frame 8
