# Microsoft 365 Security Assessment

**Prepared for:** 
**Report Date:** May 12, 2026
**Prepared by:** NRG Technology Services
**Tool Version:** NRG-Assessment v4.0.0

---

## 1. Executive Summary

### Overall Posture: 🟡 Moderate

| Metric | Value |
|---|---|
| NRG Composite Score | **70 / 100** |
| Controls Satisfied | 13 |
| Partial | 5 |
| Gaps | 4 |
| Not Applicable | 18 |
| Total | 40 |

### Top 5 Priority Actions

1. 🔴 **Critical** — SMTP client authentication disabled tenant-wide
2. 🟠 **High** — POP3 disabled for all mailboxes
3. 🟠 **High** — IMAP disabled for all mailboxes

### Service Connections

| Service | Connected |
|---|---|
| Graph | ✗ |
| EXO | ✓ |
| IPPSSession | ✓ |
| Teams | ✓ |
| SharePoint | ✗ |

---

## 2. Findings

### Defender

| State | Severity | Control | Detail |
|---|---|---|---|
| 🟡 Partial | High | Safe Attachments policy with Block action | Safe Attachments Block policy exists but has no active rule applying it to recipients. |
| 🟡 Partial | High | Safe Links policy enabled tenant-wide | Safe Links policy configured but no active rule applies it to recipients. |
| 🟢 Pass | Informational | Anti-phishing policy with impersonation protection | Anti-phishing policy with impersonation protection active. |

### Email Security

| State | Severity | Control | Detail |
|---|---|---|---|
| 🔴 Gap | Medium | Customer Lockbox enabled | Customer Lockbox is disabled. Microsoft support can access tenant data during support incidents without explicit approval. |
| 🔴 Gap | High | IMAP disabled for all mailboxes | IMAP enabled on 69 of 69 mailboxes. IMAP uses basic auth, bypassing MFA and Conditional Access. |
| 🔴 Gap | High | POP3 disabled for all mailboxes | POP3 enabled on 69 of 69 mailboxes. POP3 uses basic auth, bypassing MFA and Conditional Access. |
| 🔴 Gap | Critical | SMTP client authentication disabled tenant-wide | SMTP AUTH enabled tenant-wide. Approximately 69 of 69 mailboxes accept SMTP basic auth, bypassing MFA. |
| 🟡 Partial | Medium | DMARC enforcement policy: ndaco.org | ndaco.org DMARC at p=quarantine. Move to p=reject after verifying clean mail stream. |
| 🟡 Partial | Medium | MTA-STS policy enforced: ndaco.org | ndaco.org has MTA-STS TXT record but policy file mode could not be determined (mode: unreadable). Policy file may be unreachable. |
| 🟡 Partial | Medium | MTA-STS policy enforced: nrgtechservices.com | nrgtechservices.com has MTA-STS TXT record but policy file mode could not be determined (mode: unreadable). Policy file may be unreachable. |
| 🟢 Pass | Informational | DKIM signing enabled: ndaco.org | Both DKIM selectors published for ndaco.org. |
| 🟢 Pass | Informational | DKIM signing enabled: nrgtechservices.com | Both DKIM selectors published for nrgtechservices.com. |
| 🟢 Pass | Informational | DMARC enforcement policy: nrgtechservices.com | nrgtechservices.com DMARC at p=reject - exact-domain spoofing prevented. |
| 🟢 Pass | Informational | DNSSEC enabled for sending domains: ndaco.org | ndaco.org has DNSSEC enabled (DS records present). DNS records are cryptographically signed. |
| 🟢 Pass | Informational | DNSSEC enabled for sending domains: nrgtechservices.com | nrgtechservices.com has DNSSEC enabled (DS records present). DNS records are cryptographically signed. |
| 🟢 Pass | Informational | Mailbox audit enabled tenant-wide | Tenant audit enabled. No mailboxes have AuditBypassEnabled. |
| 🟢 Pass | Informational | Modern authentication enabled for Exchange Online | Modern authentication (OAuth2) enabled for Exchange Online. Outlook and mail clients can use MFA. |
| 🟢 Pass | Informational | Shared mailbox sign-in disabled | All 22 shared mailboxes have direct sign-in disabled. |
| 🟢 Pass | Informational | SPF record published: ndaco.org | ndaco.org has SPF with hard fail (-all). |
| 🟢 Pass | Informational | SPF record published: nrgtechservices.com | nrgtechservices.com has SPF with hard fail (-all). |
| 🟢 Pass | Informational | TLS-RPT configured for sending domains: ndaco.org | ndaco.org TLS-RPT configured. TLS delivery failure reports will be received. |
| 🟢 Pass | Informational | TLS-RPT configured for sending domains: nrgtechservices.com | nrgtechservices.com TLS-RPT configured. TLS delivery failure reports will be received. |

### Identity

| State | Severity | Control | Detail |
|---|---|---|---|
| ⬜ N/A | Medium | Authenticator app number matching enabled | AAD-Users collector data unavailable — cannot assess auth method policy. |
| ⬜ N/A | Medium | Block legacy authentication protocols | Conditional Access data not collected |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-1.1 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.1 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.2 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.3 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.4 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.5 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.6 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | MFA Assessment — AAD-2.1 | AAD-Users collector did not run. |
| ⬜ N/A | Medium | MFA Assessment — AAD-2.2 | AAD-Users collector did not run. |
| ⬜ N/A | Medium | MFA Assessment — AAD-2.4 | AAD-Users collector did not run. |
| ⬜ N/A | Medium | Phishing-resistant MFA enforced for privileged roles | CA data not collected |
| ⬜ N/A | Medium | Privileged Access Assessment — AAD-4.1 | AAD-Roles collector did not run. |
| ⬜ N/A | Medium | Privileged Access Assessment — AAD-4.2 | AAD-Roles collector did not run. |
| ⬜ N/A | Medium | Privileged Access Assessment — AAD-4.3 | AAD-Roles collector did not run. |
| ⬜ N/A | Medium | Privileged Access Assessment — AAD-4.4 | AAD-Roles collector did not run. |
| ⬜ N/A | Medium | Privileged Access Assessment — AAD-4.5 | AAD-Roles collector did not run. |

---

## 3. Configuration Inventory

Data collected during this assessment. Use as your reference baseline.

### DNS Email Security

| Domain | SPF | DKIM | DMARC Policy | DMARC Record | MTA-STS |
|---|---|---|---|---|---|
| ndaco.org | ✓ -all | ✓ Both selectors | ~ quarantine | v=DMARC1; p=quarantine; rua=mailto:dmarc@nrgtechservices.... | present |
| nrgtechservices.com | ✓ -all | ✓ Both selectors | ✓ reject | v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; ... | present |

### Exchange Online Configuration

| Setting | Value |
|---|---|
| Mailbox Audit | ✓ Enabled |
| Customer Lockbox | ✗ Disabled |
| SMTP Client Auth | ✗ Enabled (risk) |
| Total Mailboxes | 69 |
| POP3 Enabled | 69 mailboxes |
| IMAP Enabled | 69 mailboxes |
| ActiveSync Enabled | 69 mailboxes |
| Audit Bypass | ✓ None |
| Shared Mailboxes | 22 |

---

*Prepared by NRG Technology Services | (701) 250-9400 | https://www.nrgtechservices.com*
*Read-only assessment — no configuration changes were made*

