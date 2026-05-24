# Authorized Service Exposure Review

**Generated:** 2026-05-24T00:00:00Z
**Scope:** Home lab demonstration assets
**Purpose:** Defensive service exposure review and analyst documentation practice

> This report is an example artifact for authorized blue-team learning. It demonstrates how raw port results can be converted into analyst follow-up questions.

| Target | IP | Hostname | Port | Service | Analyst Note |
|---|---|---|---:|---|---|
| lab-web01 | 192.168.56.10 | lab-web01.local | 80 | HTTP | Verify redirect to HTTPS and confirm expected application owner. |
| lab-web01 | 192.168.56.10 | lab-web01.local | 443 | HTTPS | Confirm certificate validity, patch status, and application owner. |
| lab-win01 | 192.168.56.20 | lab-win01.local | 445 | SMB | Verify patching, SMB signing, share permissions, and network segmentation. |
| lab-win01 | 192.168.56.20 | lab-win01.local | 3389 | RDP | Verify MFA, VPN or jump-host access, and account lockout policy. |

## Analyst Follow-Up

The immediate concern in this sample is not that services exist. The concern is whether each service is expected, owned, patched, monitored, and restricted to the proper network segment. Remote administration services such as SSH and RDP should have stronger access controls than general user-facing services.

## Defensive Takeaways

This type of report supports asset inventory, basic exposure management, and SOC triage preparation. A junior analyst should be able to explain which assets were reviewed, what was found, why the finding matters, and what validation step should happen next.
