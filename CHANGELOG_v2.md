# Incident Trace CTF v2.0 — change log

Based on the existing Version 5 multiplayer CTF incident engine, with the changes requested after the UX refresh.

1. **Mission brief:** full mission description; opening alert visible by default on desktop/mobile.
2. **Menu duplication:** one responsive navigation source; fixed duplicate nav and mobile title squeeze.
3. **Logs:** full synthetic raw event strings and parsed fields in Inspect.
4. **Network details:** unobtrusive inspection pane, no highlighted “visibility limitation” callouts; structurally coherent cleartext SMB2 CREATE request with filename bytes.
5. **CTF flags:** two evidence-derived, server-verified artifact questions per scenario. Must inspect source event. Incorrect answers incur 3 simulated minutes; correct answers 1 minute; seven of the original score points reallocated to flags.
6. **WinRM:** reconstructed, unprotected SOAP commands in deliberately permissive fictional training setup.
7. **HTTPS:** configured TLS inspection point provides HTTP application streams including requests and responses, rather than pretending raw TLS payload is plaintext.
8. **Brand:** renamed application to **Incident Trace CTF**; kept internal Docker identifiers for volume compatibility.
9. **New scenario:** The Hidden Handler, a webshell investigation featuring HTTP POST command reconstruction, web-server child processes, archive staging and HTTP upload acknowledgment.
10. **No specialists:** no lead, support, character roster, or role-dependent bonuses; identical fixed response proficiency across competitors.
11. **Complete evidence:** each scenario includes complementary Logs, Network, Endpoint information to establish its intended intrusion sequence and incident impact, with corroboration for claims about received data and industrial command response.

Competition rules: **four sequential mandatory scenarios**, 100 points each, 400 total; shared leaderboard, one attempt per stage, saved progress, admin-only reset. The current tournament's private seed varies selected flag values so simply reading static GitHub sources doesn't expose every live answer.

## Important upgrade note

Scoring has changed, so earlier three-scenario scoreboards cannot be fairly compared with the new four-scenario results. An administrator should reset the tournament to start a new competition, but the application will never silently delete previously stored player data. Preserving the original Docker Compose service/volume identifiers allows in-place upgrades.
