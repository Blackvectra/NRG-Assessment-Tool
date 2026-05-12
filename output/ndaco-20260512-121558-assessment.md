# Microsoft 365 Security Assessment

**Prepared for:** ndaco.org
**Report Date:** May 12, 2026
**Prepared by:** NRG Technology Services
**Tool Version:** NRG-Assessment v4.5.0

---

## 1. Executive Summary

### Overall Posture: 🟠 Weak

| Metric | Value |
|---|---|
| NRG Composite Score | **44 / 100** |
| Controls Satisfied | 21 |
| Partial | 7 |
| Gaps | 28 |
| Not Applicable | 19 |
| Total | 75 |

### Top 5 Priority Actions

1. 🔴 **Critical** — Conditional Access: MFA required for all users on all cloud apps
2. 🔴 **Critical** — No on-premises synced accounts hold Entra ID admin roles
3. 🔴 **Critical** — SMTP client authentication disabled tenant-wide
4. 🟠 **High** — MFA registered for all enabled user accounts
5. 🟠 **High** — iOS App Protection (MAM) policy configured

### Service Connections

| Service | Connected |
|---|---|
| Graph | ✓ |
| EXO | ✓ |
| IPPSSession | ✗ |
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
| 🔴 Gap | Medium | Customer Lockbox enabled | Customer Lockbox disabled. Microsoft support engineers can access tenant data without explicit approval. |
| 🔴 Gap | High | IMAP disabled for all mailboxes | IMAP enabled on 69 of 69 mailboxes. IMAP uses basic authentication and cannot enforce MFA. |
| 🔴 Gap | High | POP3 disabled for all mailboxes | POP3 enabled on 69 of 69 mailboxes. POP3 uses basic authentication and cannot enforce MFA. |
| 🔴 Gap | Critical | SMTP client authentication disabled tenant-wide | SMTP AUTH enabled tenant-wide. Approximately 69 of 69 mailboxes accept SMTP basic auth, bypassing MFA. |
| 🟡 Partial | Medium | DMARC enforcement policy: ndaco.org | ndaco.org DMARC at p=quarantine. Move to p=reject after verifying clean mail stream. |
| 🟡 Partial | Medium | MTA-STS policy enforced: ndaco.org | ndaco.org MTA-STS policy state: System.Collections.Hashtable |
| 🟡 Partial | Medium | MTA-STS policy enforced: nrgtechservices.com | nrgtechservices.com MTA-STS policy state: System.Collections.Hashtable |
| 🟢 Pass | Informational | DKIM signing enabled: ndaco.org | Both DKIM selectors published for ndaco.org. |
| 🟢 Pass | Informational | DKIM signing enabled: nrgtechservices.com | Both DKIM selectors published for nrgtechservices.com. |
| 🟢 Pass | Informational | DMARC enforcement policy: nrgtechservices.com | nrgtechservices.com DMARC at p=reject - exact-domain spoofing prevented. |
| 🟢 Pass | Informational | DNSSEC enabled for sending domains: ndaco.org | ndaco.org has DNSSEC enabled (DS records present). DNS records are cryptographically signed. |
| 🟢 Pass | Informational | DNSSEC enabled for sending domains: nrgtechservices.com | nrgtechservices.com has DNSSEC enabled (DS records present). DNS records are cryptographically signed. |
| 🟢 Pass | Informational | Mailbox audit enabled tenant-wide | Tenant audit enabled. No mailboxes have AuditBypassEnabled. |
| 🟢 Pass | Informational | Modern authentication enabled for Exchange Online | Modern authentication (OAuth2) enabled for Exchange Online. Outlook and mail clients can use MFA. |
| 🟢 Pass | Informational | Shared mailbox sign-in disabled | All 22 shared mailbox(es) have sign-in disabled. |
| 🟢 Pass | Informational | SPF record published: ndaco.org | ndaco.org has SPF with hard fail (-all). |
| 🟢 Pass | Informational | SPF record published: nrgtechservices.com | nrgtechservices.com has SPF with hard fail (-all). |
| 🟢 Pass | Informational | TLS-RPT configured for sending domains: ndaco.org | ndaco.org TLS-RPT configured. TLS delivery failure reports will be received. |
| 🟢 Pass | Informational | TLS-RPT configured for sending domains: nrgtechservices.com | nrgtechservices.com TLS-RPT configured. TLS delivery failure reports will be received. |

### Identity

| State | Severity | Control | Detail |
|---|---|---|---|
| 🔴 Gap | High | Authenticator app number matching enabled | Push notifications without number matching are vulnerable to MFA fatigue (T1621). Attacker spams approvals until user accepts. |
| 🔴 Gap | High | Break-glass Global Administrator account exists | No break-glass account candidates identified. All GA accounts have recent sign-ins and/or assigned licenses — inconsistent with a dedicated break-glass pattern. Without break-glass, a failed MFA provider or misconfigured CA policy can lock all admins out of the tenant permanently. |
| 🔴 Gap | Critical | Conditional Access: MFA required for all users on all cloud apps | No enabled CA policy requires MFA for All users on All cloud apps. Compromised credentials provide immediate account access. |
| 🔴 Gap | High | Conditional Access: MFA required for Azure management | No enabled CA policy enforces MFA for Azure management (Azure portal, CLI, PowerShell). App ID: 797f4846-ba00-4fd7-ba43-dac1f8f63013. |
| 🔴 Gap | High | Conditional Access: Sign-in risk policy configured (Entra ID P2) | No CA policy found targeting sign-in risk levels. Entra ID Protection signals (impossible travel, malicious IP, atypical behavior) are generated but not acted upon. |
| 🔴 Gap | High | Conditional Access: User risk policy configured (Entra ID P2) | No CA policy targeting user risk. Leaked credential detection and persistent behavioral anomalies do not result in automated account action. |
| 🔴 Gap | High | Global Administrator accounts are dedicated (no assigned licenses) | Licensed GA accounts are daily-use accounts — exposed to phishing, malware, and browser-based attacks during normal work. A compromised daily-use account with GA is an immediate full-tenant compromise. |
| 🔴 Gap | High | MFA registered for all enabled user accounts | MFA registration critically low at 46.1%. Enforcing AAD-3.1 CA MFA policy at this registration level will lock out 55 users. |
| 🔴 Gap | Critical | No on-premises synced accounts hold Entra ID admin roles | On-prem AD compromise (DCSync, credential dump, domain takeover) directly produces Entra Global Admin access via Entra Connect sync. This is a complete hybrid identity kill chain (T1078.002). |
| 🔴 Gap | High | PIM used for Global Administrator role (JIT access model) | PIM is available but not consistently applied to the Global Administrator role. Permanent standing access means a compromised admin account immediately has full tenant privileges. |
| 🟡 Partial | Medium | No Conditional Access policies remaining in report-only mode | Report-only policies provide zero enforcement. They generate logs but do not block or require anything. |
| 🟢 Pass | Informational | Block legacy authentication protocols | Legacy authentication blocked by 2 Conditional Access policy(ies). |
| 🟢 Pass | Informational | Conditional Access: Legacy authentication blocked |  |
| 🟢 Pass | Informational | Global Administrator count between 2 and 5 |  |
| 🟢 Pass | Informational | MFA enforced via Conditional Access (not per-user MFA or Security Defaults) |  |
| 🟢 Pass | Informational | Phishing-resistant MFA enforced for privileged roles | Phishing-resistant authentication strengths applied to privileged role(s): Modern MFA (Admins |
| 🟢 Pass | Informational | Security Defaults disabled in favor of Conditional Access |  |

### Intune

| State | Severity | Control | Detail |
|---|---|---|---|
| 🔴 Gap | High | Android App Protection (MAM) policy configured | No Android App Protection policy configured. Corporate data on Android personal devices has no controls. Data can be copied to personal apps, screenshots can be taken, and data cannot be remotely wiped. |
| 🔴 Gap | High | Intune MDM authority configured and devices enrolled | Intune device management data not accessible. MDM may not be configured or the tenant does not have an Intune license. |
| 🔴 Gap | High | iOS App Protection (MAM) policy configured | No iOS App Protection policy configured. Corporate data accessed via Outlook, Teams, or OneDrive on personal iOS devices has no copy/paste, screenshot, or backup restrictions. If a device is lost or an employee leaves, data cannot be remotely wiped. |
| 🔴 Gap | High | Microsoft Defender for Endpoint connector enabled in Intune | No Microsoft Defender for Endpoint connector found in Intune. MDE threat risk scores are not integrated with device compliance, meaning compromised devices remain "compliant" in Intune. |
| 🔴 Gap | High | Windows device compliance policy requires antivirus and firewall | No Windows compliance policy requires antivirus or firewall. Endpoints can be enrolled as "compliant" with no AV or firewall active. |
| 🔴 Gap | Medium | Windows Hello for Business policy configured in Intune | No Windows Hello for Business policy found. Windows sign-in defaults to password only on enrolled devices. WHfB provides phishing-resistant biometric/PIN authentication at the device level. |
| 🟡 Partial | Medium | Enrollment restrictions configured beyond default allow-all policy | No custom enrollment restrictions found. The default policy allows all device types (Android, iOS, Windows, macOS) to enroll without restriction. Personal/unmanaged devices can enroll without controls. |
| 🟢 Pass | Informational | Windows device compliance policy requires BitLocker encryption |  |

### Power Platform

| State | Severity | Control | Detail |
|---|---|---|---|
| 🟢 Pass | Informational | Power Platform admin role assignments minimal |  |
| ⬜ N/A | Medium | Default environment DLP policy configured | Power Platform DLP data not available. Install Microsoft.PowerApps.Administration.PowerShell for full DLP assessment: Install-Module Microsoft.PowerApps.Administration.PowerShell |
| ⬜ N/A | Medium | High-risk connectors blocked in Power Platform DLP policies | Power Platform DLP data not available. Install Microsoft.PowerApps.Administration.PowerShell for DLP connector assessment. |
| ⬜ N/A | Medium | Non-default Power Platform environments covered by DLP policy | Power Platform DLP data not available. Install Microsoft.PowerApps.Administration.PowerShell. |
| ⬜ N/A | Medium | Power Platform tenant isolation enabled | Tenant isolation data not available via Graph beta API. Verify Power Platform is provisioned in this tenant. |

### Purview

| State | Severity | Control | Detail |
|---|---|---|---|
| ⬜ N/A | Medium | Audit log retention configured (90 days minimum) | Purview collector did not run. |
| ⬜ N/A | Medium | DLP policy covers Exchange email | Purview collector did not run. |
| ⬜ N/A | Medium | DLP policy covers Microsoft Teams | Purview collector did not run. |
| ⬜ N/A | Medium | DLP policy covers SharePoint and OneDrive | Purview collector did not run. |
| ⬜ N/A | Medium | Retention policy for Exchange email configured | Purview collector did not run. |
| ⬜ N/A | Medium | Retention policy for SharePoint and OneDrive configured | Purview collector did not run. |
| ⬜ N/A | Medium | Sensitivity labels published to users | Purview collector did not run. |
| ⬜ N/A | Medium | Unified audit log enabled | Purview collector did not run. |

### SharePoint

| State | Severity | Control | Detail |
|---|---|---|---|
| ⬜ N/A | Medium | Anyone link expiration enforced (30 days or less) | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | Default sharing link type set to internal or specific people | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | External user resharing of content disabled | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | Guest user resharing of items they do not own disabled | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | OneDrive default sharing link scoped to organisation | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | SharePoint tenant external sharing restricted | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | Unmanaged device access policy limits or blocks SharePoint access | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |

### Teams

| State | Severity | Control | Detail |
|---|---|---|---|
| 🔴 Gap | High | Anonymous meeting join disabled | Unauthenticated anonymous users can join Teams meetings. Anyone with the meeting link can attend without signing in, with no audit trail. |
| 🔴 Gap | Low | Email integration into Teams channels disabled | Teams channels accept email via a channel email address. Anyone who discovers or is given a channel email address can post content directly into Teams, bypassing message controls. |
| 🔴 Gap | High | Meeting lobby enabled for external and anonymous users | Meeting lobby is bypassed for everyone including anonymous users. Anyone with a meeting link joins directly without host approval. |
| 🔴 Gap | Medium | Meeting presenter role restricted to organiser or co-organisers | Anyone in a meeting can present by default. External attendees can share screens and content without restriction. |
| 🔴 Gap | Medium | PSTN (dial-in) users bypass lobby disabled | PSTN (dial-in) users bypass the meeting lobby. Callers with the conference number and ID join directly without host approval. |
| 🔴 Gap | Medium | Teams consumer (personal account) federation disabled | Teams users can communicate with Teams personal (consumer) accounts. This allows unmanaged, unsecured personal accounts to interact with internal users and potentially exfiltrate data. |
| 🔴 Gap | Medium | Teams external access (federation) restricted | Teams federation is enabled with all external organisations. Any Teams user globally can contact your users and initiate chats or calls. |
| 🔴 Gap | Low | Third-party cloud storage apps disabled in Teams | Third-party cloud storage enabled in Teams: GoogleDrive, Box, DropBox, ShareFile. Users can share files from unmanaged external storage, bypassing DLP and retention policies. |

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

