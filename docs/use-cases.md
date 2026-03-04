Where does Nomos actually get used in the real world?

Below are **real deployment scenarios**, not theoretical ones. Each includes:

* Who uses it
* What risk exists
* How Nomos sits in the architecture
* What Nomos enforces

---

# 🧑‍💻 1. AI Coding Agents in CI

## Scenario

A company lets an AI agent:

* Modify code
* Run tests
* Open PRs
* Call APIs
* Possibly deploy artifacts

This is high risk.

## Without Nomos

Agent has:

* GitHub token
* CI secrets
* Network access
* Ability to run shell commands

If compromised:

* Can exfiltrate secrets
* Can push malicious code
* Can hit arbitrary APIs
* Can loop and burn compute

---

## With Nomos

Architecture:

```text
Agent (Codex / Claude Code / custom)
        ↓ MCP
Nomos Gateway (PEP)
        ↓
Policy Engine (PDP)
        ↓
Sandbox Executor
        ↓
GitHub / HTTP / Filesystem
```

Nomos enforces:

* `repo.apply_patch` allowed only on the governed repository surface
* `process.exec` limited to `["go", "test"]`
* `net.http_request` allowlisted to `api.github.com`
* Output caps
* Sensitive actions require approval
* Secrets never returned to agent

### Result

You get:

* Bounded autonomy
* No raw credentials in agent
* Audit trail per PR
* Deterministic policy decisions

---

# ☁️ 2. Production AI Operator in Kubernetes

## Scenario

A platform team runs an AI operations agent that:

* Scales deployments
* Restarts pods
* Updates config
* Calls internal APIs

Without enforcement, that’s terrifying.

---

## With Nomos (Strong Guarantee Mode)

Deployment:

* Agent pod has **no egress**
* Agent has no K8s credentials
* All side effects must go through Nomos
* Nomos runs with workload identity
* K8s network policy enforces deny-by-default

Nomos does not ship native `k8s.*` action types in v1. In this deployment shape, it mediates the control-plane boundary through current v1 primitives such as:

* `net.http_request` to an internal control-plane API
* strict network allowlists
* approvals required for production changes
* full audit with `policy_bundle_hash`

Now you’ve turned an autonomous infra agent into:

> A governed control-plane extension.

---

# 🏦 3. Finance / Enterprise Automation Agent

## Scenario

AI handles:

* Invoice processing
* ERP updates
* Internal database updates
* External API reconciliation

Risk:

* Money movement
* Data leakage
* Compliance violations

---

## With Nomos

Nomos governs:

* `net.http_request` allowlisted to specific domains
* `secrets.checkout` short TTL and bound to trace
* `fs.write` limited to specific directories
* Large IO flagged via risk flags
* Approvals required for transactions > threshold

Audit provides:

* Who authorized
* Which policy bundle
* What version of engine
* What action fingerprint

Now the AI is:

> Compliant-by-design.

---

# 🧪 4. Autonomous Research Agent (Data Safety)

## Scenario

AI agent:

* Scrapes web
* Calls APIs
* Stores datasets
* Summarizes reports

Risk:

* Scrapes restricted domains
* Leaks proprietary data
* Downloads malware

---

## With Nomos

Nomos enforces:

* Host allowlist
* Redirect hop checks
* Output redaction
* File containment
* Output caps
* Circuit breakers on fan-out

---

# 👨‍💻 5. Developer Laptop (Best-Effort Mode)

## Scenario

Engineer runs AI locally.

You already model this correctly:

* Cannot guarantee mediation
* But can enforce publish boundary

Nomos here provides:

* Diff validation before PR
* Policy explain
* Deny unsafe repo changes
* Audit event before push

It’s Best-Effort Mode only on laptops.

---

# 🔥 Concrete Example: Real Deployment Walkthrough

Let’s say a startup wants AI to automatically:

* Refactor code
* Run tests
* Open PR

You would:

1. Deploy Nomos in CI
2. Load `safe-dev` or `safe-dev-hardened` policy pack
3. Deny all exec by default
4. Allow:

   * `fs.read`
   * `repo.apply_patch`
   * `process.exec` only for test commands
   * `repo.validate_change_set` before PR creation
5. Require approval for:

   * Large diffs
   * Changes outside `src/`
6. Enable redaction + audit JSONL export

Now they can safely:

* Turn AI loose on codebase
* Without handing it a GitHub PAT
* Without risking secret leaks
* With full traceability
