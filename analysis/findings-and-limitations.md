# Findings and Limitations — CB-002

## Supported findings
1. W04–W06 record three failed Windows network logons for `amara` on CB-FILE-01 from `198.51.100.77`; W07 records a success from the same source.
2. A01 was generated one second after W07 and matched the three-failure-then-success pattern.
3. L01 and L02 record failed SSH password authentication for `amara` on CB-LINUX-01 from the same source; L03 records a successful password authentication.
4. E01 contains urgency and asks the recipient to enter an account password through a billing-review link.
5. Supplied packet references show DNS activity for `billing-review.example`, an HTTP GET to `/review`, an HTTP 200 response, and later TLS application data.

## Not established
- The identity or location of the person using source IP `198.51.100.77`.
- Whether the successful authentications were authorized.
- Whether Amara clicked the email link or submitted credentials.
- Whether the TLS application data contained credentials or other sensitive content.
- Whether malware ran, a host was compromised, or data was accessed or exfiltrated.
- A causal link between the email and the authentication activity.
- A link between L04 and the suspicious events.

## Evidence gaps
- Full Windows/Linux event exports and host audit context.
- Original email headers and gateway records.
- Full packet capture/packet bytes and original Wireshark screenshots.
- Endpoint process, browser, DNS, and network telemetry.
- Identity-provider, VPN, session, and subsequent resource-access logs.

## Handling note
Treat temporal proximity and matching source IP as correlation, not proof of common actor or causation. Keep original timestamps and zones, preserve originals, and document any future collection with provenance and hashes.
