# Rules of Engagement (RoE) – Web Application Security Assessment

**Document Reference:** VA-ROE-[YEAR]-[NUMBER]
**Classification:** CONFIDENTIAL
**Status:** ☐ Draft  ☐ Under Review  ☑ Approved

---

## 1. Parties

| Role | Name | Organisation | Signature | Date |
|------|------|-------------|-----------|------|
| Authorising Officer | | | | |
| Security Assessor (Intern) | | | | |
| IT/Systems Owner | | | | |
| Supervisor / Mentor | | | | |

---

## 2. Scope

### 2.1 In-Scope Systems

| System | URL / IP | Environment | Owner |
|--------|----------|-------------|-------|
| | | Staging | |
| | | UAT | |

> ⚠️ **PRODUCTION SYSTEMS ARE STRICTLY OUT OF SCOPE** unless explicitly listed above with written approval from the CIO/CISO.

### 2.2 Out-of-Scope Systems

- All production/live systems not listed in 2.1
- Third-party integrated services
- Network infrastructure (switches, routers, firewalls)
- Endpoints and workstations
- Physical premises

---

## 3. Testing Window

| Parameter | Detail |
|-----------|--------|
| **Start Date & Time** | |
| **End Date & Time** | |
| **Permitted Hours** | Monday–Friday, 09:00–17:00 (local time) |
| **Emergency Stop Contact** | |
| **Emergency Stop Number** | |

---

## 4. Permitted Activities

- ☑ Automated web scanning (OWASP ZAP passive + active)
- ☑ Spider / crawling of in-scope URLs
- ☑ Manual testing of web forms and parameters
- ☑ Review of HTTP response headers and cookies
- ☐ Denial of Service (DoS) testing — **PROHIBITED**
- ☐ Social engineering — **PROHIBITED**
- ☐ Physical access testing — **PROHIBITED**
- ☐ Credential brute-forcing against production accounts — **PROHIBITED**

---

## 5. Test Accounts

| Username | Role | Purpose |
|----------|------|---------|
| `va_test_user` | Standard User | Standard workflow testing |
| `va_test_admin` | Administrator | Privileged function testing |

> All test accounts are to be **disabled and removed** after the assessment window.

---

## 6. Data Handling

- All findings and evidence are **CONFIDENTIAL**
- Raw scan data, screenshots, and reports must be stored only on the authorised assessment workstation
- No findings may be stored on personal devices or personal cloud storage
- Report must be delivered via encrypted email or secure government file transfer

---

## 7. Incident Response

If a critical vulnerability is discovered (e.g. data exposure, authentication bypass):

1. **Stop** further testing immediately
2. **Notify** the Supervisor / IT Owner within 30 minutes
3. **Document** the finding details (URL, parameter, evidence)
4. **Do not** exploit beyond proof-of-concept
5. **Await** further instructions before resuming

---

## 8. Legal Basis

This assessment is conducted under the authority of:

> [Insert relevant government IT security policy / legislation]

Unauthorised access to computer systems is a criminal offence under [applicable law]. This document grants limited, time-bound authorisation only to the named assessor(s) for the systems listed in Section 2.

---

*All parties acknowledge they have read, understood, and agree to abide by these Rules of Engagement.*
