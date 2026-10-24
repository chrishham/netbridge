# netbridge — Roadmap & εκκρεμότητες

Tunnel laptop ↔ VDI: relay (k3s), Windows agent, socks-proxy (+ exe), plugin system, e2e gate.
Λεπτομέρειες ανά feature: `docs/superpowers/specs/`, `docs/superpowers/plans/`, `docs/SECURITY_REVIEW_2026-05-21.md`.
Ημερομηνιακές υπενθυμίσεις: Google Calendar μέσω `remind` (skill `reminders`).

## Φάσεις

| Φάση | Τι | Κατάσταση |
|---|---|---|
| 1 | Plugin system + install UX (agent-v1.7.0, socks-v1.2.0) | ✅ 2026-05-21 |
| 2 | Agent auto-update, connection stability | ✅ (εκτίμηση, plans 2026-08/09) |
| 3 | E2E gate: release-binary, auth, fault/reconnect, coverage gate, error-path gapfill (PR #16, #20–#24) | ✅ |
| 4 | Release gates (#25), structured connect error codes (#26) | ✅ 2026-10-04 |
| 5 | Relay auth-first limits, JWKS bounds, trusted-proxy client IP (#27) | ✅ |
| 6 | Topology e2e πίσω από TLS edge, CI + Windows exe `--edge` (9ad0665) | ✅ |
| 7 | Windows unit tests στο CI (#29), relay message backpressure (#30), timeouts σε όλα τα jobs | ✅ 2026-10-04 |
| 8 | Επόμενα: βλ. Εκκρεμότητες | ⏳ |

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
- [ ] Απόφαση infra hardening στο kantoliana-infra: Cloudflare-only 80/443, κλείσιμο 6443, NetworkPolicy.
- [ ] Απόφαση για real e2e με staging relay + πραγματικό Entra μέσω GitHub OIDC: επιτρέπεται Entra federation; γίνεται staging namespace στο cluster;
- [ ] Προμήθεια code signing certificate για production builds (TODO στα `netbridge-agent/*.spec`).
- [ ] Relay-on-laptop (Cloudflare Tunnel): προϋπόθεση να επιτρέπεται το cloudflared στα εταιρικά laptops (EDR το σημαίνει ως tunneling tool). Μέχρι να απαντηθεί, το hosted relay μένει και βελτιώνεται (HOL blocking, versioning, binary frames, dead weight).

## Εκκρεμότητες Claude

- [ ] Αντικατάσταση των ~53 πραγματικών sleeps στα tests.
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
  - Code signing: Azure Trusted Signing ως φθηνή απάντηση στο pending todo.

## Ιστορικό

- 2026-05-21: plugin system shipped (agent-v1.7.0, socks-v1.2.0).
- 2026-10-04: PR #25/#26 (release gates, connect error codes), #27 (relay auth-first limits), topology e2e.
- 2026-10-04: PR #29 (agent tests στα Windows) και #30 (relay backpressure)· releases relay 1.0.7, agent 1.10.1, socks 1.7.0.
- 2026-10-24: ROADMAP δημιουργήθηκε από ανασκόπηση repo/memory
- 2026-10-24: αρχιτεκτονική ανασκόπηση (relay-less επιλογές, HOL blocking, binary frames, dead weight)· ιδέες στο ROADMAP.
