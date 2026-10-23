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
The original working notes specify three Wireshark screenshots:
1. `ip.addr == 10.20.0.24`
2. `dns` showing frames 3 and 4
3. `http.request` showing frame 8

Those image files were not available to this publishing step, so no screenshots are represented as attached. Add the genuine screenshots under `figures/` if you want them included; use the matching captions in Section 4 of the report.
