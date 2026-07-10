# Lab 9 — Submission

> Tooling: Falco 0.43.1 (container), Conftest 0.68.2. Host: Docker Desktop on Windows (WSL2 backend).

## Task 1: Runtime Detection with Falco

### Environment blocker (honest, and the same class the lab warns about for macOS)
Falco starts, validates config, and **loads both the default ruleset and my custom rules**
(`/etc/falco/rules.d/custom-rules.yaml | schema validation: ok`), but its eBPF driver **cannot
attach the syscall tracepoints** on the Docker Desktop kernel:
```
libbpf: failed to determine tracepoint 'syscalls/sys_enter_open' perf event ID: No such file or directory
libbpf: prog 'open_e': failed to create tracepoint 'syscalls/sys_enter_open' perf event: No such file or directory
```
Result: Falco runs but is **blind** — `cat /etc/shadow`, terminal-shell, and a `/tmp` write produced
**0 alerts** (`docker logs falco | grep -c '"rule"'` → 0). I confirmed BTF *is* present
(`test -f /sys/kernel/btf/vmlinux` → OK) and tried **both** the modern-eBPF and legacy-eBPF drivers
(`FALCO_BPF_PROBE=""`) — identical failure. This is the Windows/Docker-Desktop equivalent of the
lab's documented macOS caveat: the LinuxKit/WSL2 kernel that Docker Desktop ships doesn't expose the
raw syscall tracepoints Falco needs. **Fix (for live alerts): run Falco on a real Linux kernel** —
a full WSL2 Ubuntu distro with its own Docker (not Docker Desktop), Colima, or a Linux VM. The rules
below are correct and load cleanly; they only need a kernel that lets Falco see syscalls.

### Baseline alerts A + B
Could not be captured on this kernel (Falco blind — see above). On a syscall-capable kernel the
triggers are:
```bash
docker exec -it lab9-target /bin/sh -lc 'echo test'   # → "Terminal shell in container" (default rule)
docker exec lab9-target /bin/sh -lc 'cat /etc/shadow'  # → "Read sensitive file untrusted" (default rule)
```

### Custom rule (`labs/lab9/falco/rules/custom-rules.yaml`) — loaded + schema-validated by Falco
```yaml
- rule: Write to /tmp by container
  desc: A process inside a container wrote to /tmp — often container drift / dropped tooling.
  condition: >
    open_write and container and fd.name startswith /tmp/
  output: >
    Write to /tmp by container
    (container=%container.name user=%user.name file=%fd.name cmd=%proc.cmdline image=%container.image.repository)
  priority: WARNING
  tags: [container, drift]
```
Trigger (on a syscall-capable kernel): `docker exec --user 0 lab9-target sh -lc 'echo x > /tmp/y.txt'`.

### Tuning consideration (Lecture 9 slide 8)
The "write to /tmp" rule is inherently noisy — build tools, loggers, and package managers write to
`/tmp` constantly. I'd tune it with an **`exceptions:`** block rather than a growing `and not`
chain: `exceptions: [{name: known_tmp_writers, fields: [proc.name], values: [[npm], [pip], [apt]]}]`.
The exceptions form is preferable because it's append-only data (easy to review in a PR and to
audit *why* each entry exists), whereas piling `and not proc.name=…` clauses into the condition makes
the rule progressively unreadable and easy to break. The `and not` inline form is fine for a
one-off, permanent carve-out (e.g. `and not proc.name=falcoctl`); exceptions scale to a team.

---

## Task 2: Conftest Policy-as-Code

### My policy (`labs/lab9/policies/extra/hardening.rego`)
```rego
package main
import rego.v1

podspec := input.spec.template.spec

deny contains msg if {   # 1. run as non-root (pod OR container level)
	input.kind == "Deployment"
	some c in podspec.containers
	not runs_non_root(c)
	msg := sprintf("container %q: must run as non-root (securityContext.runAsNonRoot: true)", [c.name])
}
runs_non_root(c) if c.securityContext.runAsNonRoot == true
runs_non_root(_) if podspec.securityContext.runAsNonRoot == true

deny contains msg if {   # 2. no privilege escalation
	input.kind == "Deployment"
	some c in podspec.containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("container %q: securityContext.allowPrivilegeEscalation must be false", [c.name])
}
deny contains msg if {   # 3. drop ALL capabilities
	input.kind == "Deployment"
	some c in podspec.containers
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("container %q: securityContext.capabilities.drop must include \"ALL\"", [c.name])
}
deny contains msg if {   # 4. memory limit set
	input.kind == "Deployment"
	some c in podspec.containers
	not c.resources.limits.memory
	msg := sprintf("container %q: resources.limits.memory must be set", [c.name])
}
deny contains msg if {   # 5. image pinned by digest
	input.kind == "Deployment"
	some c in podspec.containers
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q: image must be pinned by @sha256 digest, not a tag (%s)", [c.name, c.image])
}
```

### Compliant manifest passes (`juice-hardened.yaml`)
```
10 tests, 10 passed, 0 warnings, 0 failures, 0 exceptions
```

### Non-compliant manifest fails (`juice-unhardened.yaml`)
```
FAIL - juice-unhardened.yaml - main - container "juice": image must be pinned by @sha256 digest, not a tag (bkimminich/juice-shop:latest)
FAIL - juice-unhardened.yaml - main - container "juice": must run as non-root (securityContext.runAsNonRoot: true)
FAIL - juice-unhardened.yaml - main - container "juice": resources.limits.memory must be set
FAIL - juice-unhardened.yaml - main - container "juice": securityContext.allowPrivilegeEscalation must be false
FAIL - juice-unhardened.yaml - main - container "juice": securityContext.capabilities.drop must include "ALL"
10 tests, 5 passed, 0 warnings, 5 failures, 0 exceptions
```

### Compose policy generalizes (shipped `compose-security.rego`, `--namespace compose.security`)
```
# juice-compose.yml (hardened):
4 tests, 4 passed, 0 warnings, 0 failures, 0 exceptions

# /tmp/bad-compose.yml (nginx:latest, no user/read_only/cap_drop):
FAIL - bad-compose.yml - compose.security - services must set an explicit non-root user
FAIL - bad-compose.yml - compose.security - services must set read_only: true
2 tests, 2 passed, 0 warnings, 2 failures, 0 exceptions
```
The **same `deny contains msg` pattern** adapts from `input.spec.template.spec.containers` (K8s) to
`input.services` (compose) — the policy logic is identical, only the input shape differs.

### Why CI-time vs admission-time (defense in depth)
CI-time Conftest fails the **pull request** — the developer gets the feedback in seconds, before
merge, with full context. Admission-time Conftest (Kyverno/OPA-Gatekeeper) is the **backstop at
`kubectl apply`** for anything that never went through CI (a hotfix applied by hand, a Helm chart
from a third party, a compromised pipeline). Running both means a bad manifest has to defeat *two*
independent gates: you get fast, friendly developer feedback **and** a hard guarantee that nothing
non-compliant reaches the live API server regardless of how it got there.

---

## Bonus: Cryptominer Detection Rule

### Rule (`labs/lab9/falco/rules/custom-rules.yaml`) — loaded + schema-validated by Falco
```yaml
- rule: Possible Cryptominer Activity
  desc: >
    Container either connected to a well-known mining-pool port OR ran a known miner binary.
  condition: >
    container and
    (
      (evt.type in (connect, sendto) and fd.sport in (3333, 4444, 5555, 7777, 14444, 19999, 45700))
      or
      (spawned_process and proc.name in (xmrig, ethminer, cgminer, t-rex, claymore, minerd, nbminer))
    )
  output: >
    Possible cryptominer activity
    (container=%container.name proc=%proc.name cmd=%proc.cmdline target=%fd.name port=%fd.sport)
  priority: CRITICAL
  tags: [container, mitre_execution, mitre_command_and_control]
```
Trigger (on a syscall-capable kernel): `docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333'`
fires the port indicator; running a process named `xmrig` fires the process indicator. (Not
capturable here — same Falco-blind-on-Docker-Desktop kernel limitation as Task 1.)

### Reflection
- **Two indicators used:** (1) destination = a well-known mining-pool port (`fd.sport in (3333,
  4444, …)`), and (2) process name matches a known miner (`xmrig`, `ethminer`, …). They're
  independent — a miner using a non-standard port is still caught by name, and a renamed binary is
  still caught by the port — so OR-ing them lowers false negatives.
- **What it misses:** an obfuscated miner that (a) renames its binary to something innocuous AND
  (b) proxies pool traffic over **443/HTTPS** to a domain that fronts the pool. Neither indicator
  fires — the port looks like normal web traffic and the process name is unknown. That's the
  false-negative case; catching it needs behavioural signals (sustained high CPU + steady low-volume
  egress), which is metrics territory, not a syscall rule.
- **SLA-matrix integration:** this rule is `priority: CRITICAL`, so it maps to the Critical SLA row
  (24h) — but a *runtime* cryptominer alert is really an active-incident signal, not a patch-me-later
  finding, so in the Lecture 9 SLA matrix it should route to **immediate paging / containment**, not
  the normal remediation queue. It feeds Lab 10's DefectDojo as a runtime finding but with an
  escalation path distinct from scan-time CVEs.
