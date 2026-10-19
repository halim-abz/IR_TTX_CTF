# The War Room: Incident Response — v2.1

## Education and gameplay

- Renamed app and updated browser title and navigation branding.
- Two CTF flags per scenario are **mandatory for verified closure**, as are at least two evidence-backed conclusions. The closure gate is now enforced in the server for all four scenarios and displayed as a locked action while unsatisfied. Flags account for up to 7 of the original 100 score points; they are not extra credit.
- Restored optional, question-specific reasoning hints in Conclusions. Hints identify which evidence relationships to examine without identifying the correct answer.
- Explicit coaching after D20 operational actions: separate **unsafe or badly sequenced response decisions** from failures caused by an execution roll. Explain the relevant best-practice alternative.
- Timed attacker escalation remains. In addition to the original simulation effects and scoring caps, newly triggered harmful events are surfaced to the player during actions and discussed in the after-action report.
- Structured educational after-action reports now cover: assessment, what went well, what did not, missing milestones, incident escalation times, response timing, recommendations, full chronology and score details. Both completed and unsuccessful scenarios are reviewed.

## Admin and hosting

- Added password-protected `POST /api/admin/overview` endpoint with per-player stage status, scores, last activity, flag progress, conclusions, active stage, incident time, and learning issues.
- Admin UI adds sortable and filterable player overview and retains reset with confirmation.
- Kept the Docker Compose service name, persistent volume and configurable host port (3030 by default) for in-place upgrades.
- Previously stored completion histories replay using legacy accepted actions; newly executed mission closures enforce the stricter evidence requirements.

## Verification

- Four-scenario full-tournament test: 362/400, all four cases completed.
- Confirmed server rejects premature final verification before 2 flags and 2 supported conclusions.
- Confirmed unsafe decisions produce specific best-practice coaching.
- Confirmed delayed response continues to trigger attacker milestones and increased exposure.
- Browser smoke rendering of Mission, Flags, Conclusions, Admin, Mobile, and completed After-Action screens without JavaScript errors.

## Still outside the scope

- This remains a deterministic, V5-based single-service training platform, not a live NetWitness sensor interface, a fully autonomous opponent, or strong anti-Sybil identity verification.
