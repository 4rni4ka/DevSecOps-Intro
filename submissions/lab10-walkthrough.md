# 5-Minute DevSecOps Program Walkthrough — OWASP Juice Shop

> Delivery note: read aloud, this runs ~4:40. Numbers in `‹…›` come from my DefectDojo run
> (Task 1/2) — I swap in the live figure before speaking.

## (0:00–0:30) Context
I built an end-to-end DevSecOps program around **OWASP Juice Shop v20** as the target of record —
one product, tracked across its whole lifecycle. Every stage of the SDLC has a control: secrets and
signing at commit time, SBOM + SCA + SAST at build, IaC scanning + image signing + policy gates
before deploy, Falco at runtime, and **DefectDojo as the single system of record** that aggregates
all of it, deduplicates across tools, and holds everything to an SLA.

## (0:30–2:00) The layers (defense in depth)
I'll walk the pipeline top to bottom:
- **Commit** — SSH-signed commits (every commit shows GitHub "Verified"), and a `gitleaks`
  pre-commit hook that hard-blocks secrets. I proved it by planting a fake GitHub PAT — the commit
  aborted on the `github-pat` rule before the secret ever entered history.
- **Build** — `syft` generates a **CycloneDX SBOM (1,846 components)**; `grype` scans it
  (**105 findings, 7 Critical**); `semgrep` runs SAST over the source (**22 findings**, top rule =
  Sequelize SQL-injection). The SBOM is the artifact that makes the *next* Log4Shell a 30-second query.
- **Pre-deploy** — `checkov` + `KICS` scan the IaC (**78 Terraform misconfigs**, plus Ansible/Pulumi),
  with a **custom Checkov policy** for an org-specific tag rule. `cosign` **signs the image by digest**
  and attaches the SBOM as an attestation; a **Conftest/Rego gate** fails the PR if a manifest isn't
  PSS-`restricted` (non-root, drop ALL caps, no priv-esc, digest-pinned).
- **Runtime** — `Falco` with custom eBPF rules — container `/tmp`-write drift and a **cryptominer
  rule** (mining-pool port OR known-miner process name).
- **Program** — **DefectDojo** ingests every tool's output, dedups the same CVE across Grype + Trivy
  + Trivy-k8s into one finding, and applies the SLA matrix (24h / 7d / 30d / 90d).

## (2:00–3:00) Findings + closures
- Across ‹N tools› I imported ‹RAW› raw findings that dedupped to **‹UNIQUE› unique** — the dedup
  ratio alone is the argument for a system of record over per-tool spreadsheets.
- **Strongest correlated finding:** SQL injection in `routes/login.ts` — **Semgrep flagged the sink
  statically** (tainted `req.body.email` concatenated into a raw `sequelize.query`) **and ZAP reached
  the same `/rest/user/login` endpoint dynamically**. Static says *where and why*, dynamic says *it's
  actually exposed*. Fix: parameterised queries. That's my highest-confidence finding — two independent
  tools, two angles, one root cause.
- I risk-accepted ‹finding› until ‹date› because ‹reason› — and it has an **explicit expiry**, so it
  can't silently rot in the backlog.

## (3:00–4:00) Metrics
- **MTTR ‹n› days** on findings closed this term — I benchmark that against DORA Elite (< 1 day) and
  I'm honest about the gap and the plan to close it.
- **Vuln-age median ‹n› days**; **SLA compliance ‹n›%**; **backlog trend ‹stable/falling›**.
- The point isn't the absolute numbers — it's that they *exist and trend*. "We closed ‹n› Criticals,
  MTTR is moving down" is a program; "we ran some scanners" is not.

## (4:00–4:30) Next steps
If I had another quarter I'd mature **OWASP SAMM → Defect Management**: wire Falco runtime alerts into
DefectDojo as a first-class finding source (custom parser), so runtime and scan-time findings share one
SLA and one MTTR clock — closing the loop between "detected in prod" and "tracked to remediation."

## (4:30–5:00) Q&A anticipation
**Q: "Walk me through how you'd handle a Log4Shell-style 0-day."**
Because every image carries a **signed CycloneDX SBOM**, I don't guess — I query DefectDojo / the
attested SBOM by component and version and get an exact list of affected services in seconds, verify it
against the *deployed* digest (not a stale side-channel SBOM), then drive fixes through the existing
SLA clock. The SBOM turns "are we affected?" from a week of archaeology into a query.

**Q: "Why only open-source tools — no IAST or paid SAST?"**
Honest tradeoff: the OSS stack (Syft/Grype/Semgrep/Trivy/Checkov/Cosign/Falco/DefectDojo) covers
SCA, SAST, IaC, signing, runtime, and aggregation with zero license cost and full CI portability —
which is the right call for establishing the *program discipline* first. IAST/paid SAST buy lower
false-positive rates and deeper dataflow, and I'd add them once the SLA/MTTR baseline exists and the
finding volume justifies the spend — not before, or you're paying for signal you can't yet action.
