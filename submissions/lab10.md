# Lab 10 — Submission

> ⚠️ **Task 1 & 2 require a running DefectDojo (7+ containers, ~4 GB RAM).** This is the one part of
> the course that this machine's Docker Desktop can't run reliably (its WSL2 engine wedges under
> heavy multi-container load — same instability seen in Labs 5/7). Everything below is a **ready-to-run
> runbook**: run the commands, paste the real numbers into the `‹…›` slots, and this becomes the final
> submission. The **Bonus walkthrough (`lab10-walkthrough.md`) is already complete.**

## Task 1: DefectDojo Setup + Import

### Runbook (run these, then fill the values below)
```bash
# 1. Start DefectDojo (first run 5-10 min; needs Docker memory ≥ 4-6 GB — Settings→Resources)
cd labs/lab10/work
git clone https://github.com/DefectDojo/django-DefectDojo dd && cd dd
./docker/setEnv.sh dev
docker compose up -d
docker compose logs initializer | grep -i "Admin password"     # ← note the admin password

# 2. Log in at http://localhost:8080 (admin / <password>), then Profile → API v2 Key → copy token
export DD_URL="http://localhost:8080"
export DD_TOKEN="<paste token>"

# 3. Import every prior-lab report (the shipped helper resolves paths from repo root)
cd ../../../..                              # back to repo root
bash labs/lab10/imports/run-imports.sh

# 4. Counts
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?limit=1" | jq .count
```
> Note on scan files: Labs 5–7 outputs live under `labs/lab5|6|7/results/` on disk (present from
> those labs). Lab 4's `grype`/`trivy`/`cdx` are under `study/devsex/Lab34/labs/lab4/`. If any were
> cleaned, regenerate with the Lab 4–7 commands before importing.

### DefectDojo version
- Version: `‹docker compose images defectdojo-uwsgi›`

### Product + Engagement
- Product ID: `‹n›` · name: OWASP Juice Shop
- Engagement ID: `‹n›` · status: In Progress

### Imports completed
| Lab | Scan type | File | Findings |
|-----|-----------|------|---------:|
| 4 | Anchore Grype | grype-from-sbom.json | ‹n› |
| 4 | Trivy Scan | trivy.json | ‹n› |
| 5 | Semgrep JSON Report | labs/lab5/results/semgrep.json | ‹n› |
| 5 | ZAP Scan | labs/lab5/results/auth-report.json | ‹n› |
| 6 | Checkov Scan | labs/lab6/results/checkov-terraform/results_json.json | ‹n› |
| 6 | KICS Scan | labs/lab6/results/kics-ansible/results.json | ‹n› |
| 6 | KICS Scan | labs/lab6/results/kics-pulumi/results.json | ‹n› |
| 7 | Trivy Scan | labs/lab7/results/trivy-image.json | ‹n› |
| **Raw total** | | | ‹SUM› |
| **After dedup** | | | ‹UNIQUE› |

### Dedup example
- CVE/ID: `‹e.g. CVE-2019-10744›` — found by `‹Grype + Trivy + Trivy-k8s›` → DefectDojo finding #`‹n›`
  (one finding, N source scans).

---

## Task 2: Governance Report

### SLA matrix (Configuration → SLA Configuration)
Applied: **Critical 24h · High 7d · Medium 30d · Low 90d** to the engagement.

### Executive summary
Juice Shop, scanned across ‹N› tools, has **‹n› open findings** (‹n› Critical + ‹n› High). MTTR on
findings closed this period is **‹n› days**; **‹n›%** closed within SLA.

### Findings by severity (active)
| Severity | Count |
|----------|------:|
| Critical | ‹n› |
| High | ‹n› |
| Medium | ‹n› |
| Low | ‹n› |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Grype | ‹n› | ‹n› | ‹n› | ‹n› |
| Trivy | ‹n› | | | |
| Semgrep | ‹n› | | | |
| ZAP | ‹n› | | | |
| Checkov / KICS | ‹n› | | | |

### Program metrics
- MTTD: ‹n› d · MTTR: ‹n› d · Vuln-age median: ‹n› d · Backlog trend: ‹±n› · SLA compliance: ‹n›%

### Risk-accepted items (each MUST have an expiry)
| Finding | Severity | Reason | Expiry |
|---------|----------|--------|--------|
| ‹finding› | ‹sev› | ‹reason› | ‹YYYY-MM-DD› |

### Next-quarter goal (OWASP SAMM)
Mature **Defect Management**: current High MTTR is ‹n› d (target ‹n›). Add a Falco custom-parser so
runtime alerts (Lab 9) share the same SLA/MTTR clock as scan-time CVEs — closing the detect→remediate
loop across build-time and runtime findings.

---

## Bonus: Interview Walkthrough
- Script: [`submissions/lab10-walkthrough.md`](lab10-walkthrough.md) — **complete** (6 timed sections
  + 2 anticipated Q&A).
- Practiced runtime: ‹m:ss› (target ≤ 5:00)
- Strongest claim: *"The SBOM turns 'are we affected?' from a week of archaeology into a query."*
