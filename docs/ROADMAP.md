# netbridge — Roadmap & εκκρεμότητες

Tunnel laptop ↔ VDI: relay (k3s), Windows agent, socks-proxy (+ exe), plugin system, e2e gate.
Λεπτομέρειες ανά feature: `docs/superpowers/specs/`, `docs/superpowers/plans/`, `docs/SECURITY_REVIEW_2026-05-21.md`.
Ημερομηνιακές υπενθυμίσεις: Google Calendar μέσω `remind` (skill `reminders`).

## Φάσεις

| Φάση | Τι | Κατάσταση |
|---|---|---|
| 1 | Plugin system + install UX (agent-v1.7.0, socks-v1.2.0) | ✅ 2026-05-21 |
| 2 | Agent auto-update, connection stability | ✅ 2026-09-21 (auto-update 1025a82/feb153b, stability merge 9510891, updater fixes 7400699/6631d20) |
| 3 | E2E gate: release-binary, auth, fault/reconnect, coverage gate, error-path gapfill (PR #16, #20–#24) | ✅ |
| 4 | Release gates (#25), structured connect error codes (#26) | ✅ 2026-10-04 |
| 5 | Relay auth-first limits, JWKS bounds, trusted-proxy client IP (#27) | ✅ |
| 6 | Topology e2e πίσω από TLS edge, CI + Windows exe `--edge` (9ad0665) | ✅ |
| 7 | Windows unit tests στο CI (#29), relay message backpressure (#30), timeouts σε όλα τα jobs | ✅ 2026-10-04 |
| 8 | WS close diagnostics + event-loop watchdog (plan 2026-10-24-ws-close-diagnostics, 7e144a2)· το deploy/release εκκρεμεί (βλ. Εκκρεμότητες Claude) | ✅ 2026-10-24 |
| 9 | Επόμενα: βλ. Εκκρεμότητες | ⏳ |

Releases 2026-10-04: relay 1.0.7, agent 1.10.1, socks 1.7.0, socks-exe 0.5.0 (το agent-v1.10.0 είναι tag χωρίς release).

## Αποφάσεις (να μην ξαναρωτηθούν)

- Plugins: always-on υπηρεσίες· το exec toggle ελέγχει μόνο `/files` και `/exec`. Plugin install/update απαιτούν toggle· list/info/uninstall όχι.
- Plugin hostname αρχίζει με `netbridge-`· `manifest.json` υποχρεωτικό· repos στο Azure DevOps (NBGIDP/DevOps_Private/netbridge-plugins).
- `socks5h://` (με h) απαραίτητο για magic hostnames.
- `no_agent` μένει σε SOCKS 0x04 (το pinάρει το fault journey `agent_down_fails_fast`).
- Legacy connect ανέχεται αποτυχία τοπικού DNS (το Windows passthrough proxy μπορεί να λύνει ονόματα που η μηχανή δεν λύνει).
- Κάθε release workflow καλεί το `ci.yml` (`workflow_call`)· κάθε νέο CI/release job έχει timeout (2–3× κανονικής διάρκειας).
- Releases δημοσιεύουν μόνο το exe που πέρασε το e2e gate.
- Το relay καθυστερεί (δεν πετάει) μηνύματα πάνω από το όριο ρυθμού· e2e relay τρέχει στα 50 msg/s.
- `RELAY_TRUSTED_PROXIES` μένει off στο prod (το origin απαντά στο 443 παρακάμπτοντας Cloudflare).
- Βαριά jobs (vitest/coverage/Playwright) μέσω `scripts/remote-run.sh` στο cc-sandbox-dev, όχι στο laptop.
- Το `docs/` είναι gitignored: `git add -f` μόνο στα συγκεκριμένα αρχεία.

## Εκκρεμότητες χρήστη

- [ ] Prod smoke test με πραγματικούς clients μετά τα releases της 2026-10-04.
- [ ] Agent update σε v1.11.1 από το tray του VDI (Check for Updates), για να τρέξουν τα close-code logs και ο watchdog.
- [ ] Απόφαση infra hardening στο kantoliana-infra: Cloudflare-only 80/443, κλείσιμο 6443, NetworkPolicy.
- [ ] Απόφαση για real e2e με staging relay + πραγματικό Entra μέσω GitHub OIDC: επιτρέπεται Entra federation; γίνεται staging namespace στο cluster;
- [ ] Προμήθεια code signing certificate για production builds (TODO στα `netbridge-agent/*.spec`).
- [ ] QA pipeline: το `pipelines/net-bridge.yaml` (repo chamaletsos) κάνει clone το `main` HEAD· pin σε tag `relay-v*` ώστε οι QA images να ταιριάζουν με τα δοκιμασμένα releases — δική σου απόφαση (docs/superpowers/specs/2026-10-04-topology-e2e-design.md).
- [ ] Relay-on-laptop (Cloudflare Tunnel): προϋπόθεση να επιτρέπεται το cloudflared στα εταιρικά laptops (EDR το σημαίνει ως tunneling tool). Μέχρι να απαντηθεί, το hosted relay μένει και βελτιώνεται (HOL blocking, versioning, binary frames, dead weight).

## Εκκρεμότητες Claude

- [ ] Αποσυνδέσεις (έρευνα 2026-10-24): ~30 reconnects του laptop proxy σε 4 μέρες, 24/7, ανεξάρτητα από traffic. 2/3 είναι CLOSE από την πλευρά server χωρίς λόγο πουθενά (relay δεν κάνει log κανονικά connect/disconnect, proxy δεν κάνει log το close_code), 1/3 "No PONG" (σπασμένο path). Relay υγιές (19d uptime, 1m CPU). 3× "Replacing existing agent" σε 48h = ο agent επανασυνδέθηκε ενώ το relay έβλεπε την παλιά του σύνδεση ζωντανή (πιθανό HOL blocking ή σιωπηλό drop από το corporate proxy). Canary: `scratchpad/ws_canary.py` (laptop → Cloudflare → relay) καταγράφει close codes.
  - Agent logs (VDI, 2026-10-21..24): 17× "Connection closed by server" → reconnect σε 5s, μηδέν "assuming dead"/WebSocket errors → η υπόθεση HOL→liveness ΔΕΝ επιβεβαιώνεται. Οι 3 "Replacing existing agent" του relay συμπίπτουν στο δευτερόλεπτο με agent reconnects: το CLOSE έφτασε στον agent ενώ το relay leg ήταν ακόμα ανοιχτό → το κλείνει ενδιάμεσος (corporate proxy / Cloudflare), όχι το relay. Agent drops και proxy drops δεν συμπίπτουν χρονικά → ανά-σκέλος αιτίες.
  - Agent hang 2026-10-24 13:59:51→19:01:42 (v1.9.0): καμία γραμμή log για 5h (ούτε ωριαίο token refresh), proxy έβλεπε no_agent· VDI session disconnect 18:06 local (TerminalServices 59/23/39/40/24), reconnect 19:01 και restart από χρήστη. Μοναδικό τέτοιο κενό στα 3 ημερολόγια. Αίτιο άγνωστο (event loop κολλημένο; VDI frozen;). Ιδέα: watchdog thread που γράφει log αν ο loop δεν απαντήσει σε 60s.
  - Agent τρέχει v1.9.0 ενώ βγαίνει "Update available: v1.10.1": by design, το update εφαρμόζεται μόνο χειροκίνητα από το tray (notification + "Check for Updates"). Εκκρεμότητα χρήστη: να το κάνει, ή ιδέα: auto-apply σε idle.
  - Θόρυβος: εκατοντάδες "Proxy authentication required" για Firefox telemetry (corporate proxy 407 + Connection: close → skip SSPI). Αξίζει rate-limited/debug log.
  - [x] Βήμα 0 (diagnostics, υλοποιήθηκε 2026-10-24, branch ws-close-diagnostics): log close_code/reason/διάρκεια στο τέλος κάθε WS σε relay, proxy, agent· relay να κάνει log register/disconnect agent & tunnel. Μετά απόδοση των drops (Cloudflare / home ISP / relay / HOL).
    - Πώς διαβάζεται: grep `close_code=` στα logs των τριών (relay, proxy, agent) και `Event loop unresponsive` στο agent log.
    - Merged στο main 2026-10-24 (7e144a2). Review: Sonnet 3 γύροι + gpt-6.1-sol 4 γύροι (3 Medium βρέθηκαν και διορθώθηκαν: watchdog μπλόκαρε στο logging lock που διαγιγνώσκει → OS-level writes στο `watchdog.log`· απεριόριστα helper threads → ένα· αποτυχία `Thread.start()` του watchdog σταματούσε τον agent → log & ignore). Το τελευταίο fix δεν ξανα-ελέγχθηκε από reviewer (εξαντλήθηκε το budget γύρων), καλύπτεται από fault-injection test.
    - Αρχείο watchdog: `%LOCALAPPDATA%\NetBridge\logs\watchdog.log` (γράφεται και όταν το logging είναι κολλημένο).
    - Release 2026-10-24: πρώτο tagging (relay-v1.0.8, agent-v1.11.0, socks-v1.7.1, socks-exe-v0.5.1) έδωσε 0 workflow runs γιατί τα 4 tags μπήκαν σε ένα push (GitHub: >3 tags σε ένα push = κανένα push event). Κανόνας: ένα tag ανά push. relay-v1.0.8 μπλοκαρίστηκε από Trivy (aiohttp 3.14.3 HIGH×3, certifi 2026.1.4 CRITICAL emSign) → bump aiohttp 3.14.5 + certifi 2026.10.23 σε όλα τα lockfiles (eddff06) και re-tag relay-v1.0.9, agent-v1.11.1, socks-v1.7.2, socks-exe-v0.5.2.
    - [x] Deploy/release 2026-10-24: relay v1.0.9 στο k3s (rollout restart 21:48 local, pod netbridge-relay-754fddc857-9dw95, ήδη γράφει `Agent/Tunnel connected/disconnected`)· socks 1.7.2 στο laptop (brew upgrade, τρέχει με nohup `--relay <host> --no-tray`, όχι brew services· χωρίς `--no-tray` η 1.7.2 σκάει με "Namespace Gtk not available")· agent-v1.11.1 δημοσιευμένο (netbridge.exe), εκκρεμεί εφαρμογή από το tray του VDI.
    - [ ] Μετά 2–3 μέρες logs (από 2026-10-27): απόδοση των drops ανά σκέλος από τα `close_code=` σε relay/proxy/agent και έλεγχος `watchdog.log` στο VDI.
    - Canary (idle wss laptop→Cloudflare→relay, heartbeat 45s): 2026-10-24 18:33→19:50 χωρίς drop. Idle σύνδεση με pings δεν πέφτει από Cloudflare· τα drops του proxy δεν είναι idle timeout.
  - Αν Cloudflare: επιλογή grey-cloud DNS για το relay hostname (Traefik + Let's Encrypt) ή stream resumption στο πρωτόκολλο.
- [ ] Αντικατάσταση των ~53 πραγματικών sleeps στα tests.
- [ ] Flaky tests (2026-10-24): `socks-proxy-win tests/test_edgeproxy.py::test_oversized_head_answers_400` απέτυχε στο Windows e2e gate με WinError 10054 (ο server κλείνει με αδιάβαστα bytes → RST πριν ο client διαβάσει το 400· πιθανή διόρθωση: drain πριν το close). Το relay suite έδωσε 1 failure σε παράλληλο φορτίο, 0/4 μετά.
- [ ] `release-relay.yml` αποτυγχάνει σε κάθε dependabot PR από 2026-10-20 (Trivy στο PR build· τώρα που έγινε το bump πρέπει να ξαναπρασινίσει, να ελεγχθεί).
- [ ] Normalisation 6to4/Teredo στο client-IP.
- [ ] Μετάβαση του `classify_connect_error` σε codes.
- [ ] Ο modern agent αποτυγχάνει σε ονόματα που δεν λύνονται τοπικά ακόμη και με passthrough proxy (γνωστή παλιά συμπεριφορά).

## Ιδέες / μελλοντικά

- Staging relay e2e (βλ. εκκρεμότητες χρήστη).
- Αρχιτεκτονική ανασκόπηση 2026-10-24 (απόφαση χρήστη εκκρεμεί):
  - Relay στο laptop μέσω Cloudflare Tunnel (cloudflared, kantoliana.gr): ο agent συνδέεται στο hostname του laptop, το WS server μπαίνει μέσα στο socks-proxy. Καταργεί relay package, k3s/OCI/Traefik deploy, GHCR image, release-relay, infra hardening todo. Εναλλακτικά Tailscale Funnel.
  - Head-of-line blocking στον agent: `handle_tcp_data` κάνει `await writer.drain()` μέσα στο receive loop του WS· ένας αργός προορισμός παγώνει όλα τα streams. Per-stream bounded queue + task ή credit-based flow control.
  - Binary frames αντί JSON+base64 (−25% bandwidth, λιγότερο CPU στο relay/exe). Προαπαιτούμενο: protocol version negotiation στο handshake (`registered`), δεν υπάρχει σήμερα.
  - Dead weight: `legacy.py` (866 γρ.) + test_legacy, `azure-storage-blob` στο agent (δηλωμένο, δεν γίνεται import), `pyyaml` στο relay, 3 αντίγραφα tray/dialogs/installer/updater/config (agent, socks-proxy, socks-proxy-win) → κοινό package.
  - Prod auth: `NETBRIDGE_ALLOWED_USERS`/`GROUPS` δεν είναι ορισμένα (όλοι οι χρήστες 2 tenants)· ARM token ως bearer = κάθε cached ARM token δίνει πρόσβαση στο VDI του χρήστη. Επιλογή: app registration με δικό του scope.
  - Prometheus `/metrics` στο relay (streams, bytes, error codes, reconnects) → Grafana.
  - k8s: pinned image tag αντί `:latest` + pullPolicy Always.
  - Plugin `uninstall`: laptop-side cleanup (χρειάζεται convention για το τι αφαιρείται) (docs/superpowers/specs/2026-05-21-plugin-install-ux-design.md).
- Code signing: Azure Trusted Signing ως φθηνή απάντηση στο pending todo.

## Ιστορικό

- 2026-05-21: plugin system shipped (agent-v1.7.0, socks-v1.2.0).
- 2026-10-04: PR #25/#26 (release gates, connect error codes), #27 (relay auth-first limits), topology e2e.
- 2026-10-04: PR #29 (agent tests στα Windows) και #30 (relay backpressure)· releases relay 1.0.7, agent 1.10.1, socks 1.7.0.
- 2026-10-24: ROADMAP δημιουργήθηκε από ανασκόπηση repo/memory
- 2026-10-24: αρχιτεκτονική ανασκόπηση (relay-less επιλογές, HOL blocking, binary frames, dead weight)· ιδέες στο ROADMAP.
- 2026-10-24: Βήμα 0 diagnostics υλοποιήθηκε (branch ws-close-diagnostics): close_code/duration/reason logs σε relay, proxy, agent + event-loop watchdog στον agent.
- 2026-10-24: Βήμα 0 merged στο main (7e144a2) μετά από codex-review-loop (3 Medium διορθώθηκαν). Εκκρεμεί deploy/release των τριών components.
- 2026-10-24: Releases relay-v1.0.9, agent-v1.11.1, socks-v1.7.2, socks-exe-v0.5.2 (μαζί με bump aiohttp/certifi λόγω Trivy). Relay deployed, laptop socks 1.7.2 ενεργό, agent update εκκρεμεί από χρήστη. Δεύτερος χρήστης στο relay: REPPAS.NIKOLAOS.
- 2026-10-24: tidy — προστέθηκαν QA pipeline pinning (εκκρεμότητα χρήστη) και plugin uninstall cleanup (ιδέα) από τα specs· τίποτα για τικάρισμα.
- 2026-10-24: tidy — φάση 2 έκλεισε με ημερομηνία/shas (αντί εκτίμησης)· προστέθηκε φάση 8 για το plan ws-close-diagnostics (merged 7e144a2)· τα «Επόμενα» έγιναν φάση 9.
