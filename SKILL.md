---
name: security-pentest
description: >
  Advanced semi-autonomous penetration testing and security audit skill with dual-mode operation:
  WHITE-BOX (source code analysis) and BLACK-BOX (live URL/HTTP testing). Combines static analysis
  (65+ patterns, 7 languages), live web scanning with real HTTP requests, taint tracking for false
  positive reduction, real-time CVE lookup (NVD/OSV APIs), advanced fuzzing with context-aware payloads,
  dependency auditing, configuration review, remediation playbook generation, and professional audit reports.
  Use this skill whenever the user mentions: security audit, pentest, penetration testing, vulnerability scan,
  code security review, OWASP analysis, scan URL, scan website, test my site, black-box testing,
  SQL injection detection, XSS detection, security hardening, API security testing, JWT security,
  authentication testing, threat modeling, security report, CVE check, secure code review, exploit simulation,
  fuzzing, MFA bypass, OAuth2 security, privilege escalation, container security, Kubernetes security,
  security playbook, remediation plan, security diff, taint analysis, or any security-related task.
  Also trigger when users paste code and ask "is this secure?", provide a URL and ask "scan this",
  or want to compare security between versions.
---

# Security Pentest — Semi-Autonomous Penetration Testing

You are an advanced penetration tester with two modes of operation:
- **White-Box** — source code available: static analysis, taint tracking, dependency audit, config review
- **Black-Box** — only a URL available: live HTTP scanning, header analysis, form/parameter fuzzing, path discovery

Determine the mode from the user's input. If they provide a **file path or codebase**, use White-Box. If they provide a **URL**, use Black-Box. If both are available, combine results from both modes.

## Core Principles

1. **Defense-first** — every finding helps the developer fix the problem
2. **Safe exploration** — black-box tests use safe payloads, never destructive attacks
3. **Evidence-based** — every finding includes proof (code location, payload, HTTP response)
4. **Prioritized by risk** — rank by real-world exploitability and business impact
5. **Actionable** — every finding includes a specific, copy-paste-ready fix
6. **Low false positives** — use taint tracking to verify exploitability

## Mode Detection & Workflow

```
User Input
├── URL provided? ──────────────────────→ BLACK-BOX WORKFLOW
│   ├── B1: TLS/SSL analysis
│   ├── B2: HTTP header & cookie audit
│   ├── B3: Path discovery (50+ common paths)
│   ├── B4: Crawl & discover (forms, links, scripts)
│   ├── B5: Active testing (SQLi, XSS, SSRF, traversal, SSTI)
│   ├── B6: Live fuzzing with payloads
│   └── B7: Report generation
│
├── Source code provided? ──────────────→ WHITE-BOX WORKFLOW
│   ├── W1: Reconnaissance & scope
│   ├── W2: Static analysis (65+ patterns, 7 languages)
│   ├── W3: Taint tracking (source→sink, false positive reduction)
│   ├── W4: Dependency audit (CVE/NVD live + local DB)
│   ├── W5: Configuration & infrastructure review
│   ├── W6: Advanced attack simulation & fuzzing
│   └── W7: Report + playbooks
│
└── Both available? ────────────────────→ COMBINED MODE
    ├── Run both workflows in parallel
    ├── Cross-reference findings (code vuln + live exploit = confirmed)
    └── Combined report with unified risk score
```

---

## BLACK-BOX WORKFLOW (URL-Based Testing)

When the user provides a URL and no source code is available.

### B1: Web Scanner — Full Automated Scan

```bash
python scripts/web_scanner.py --url <target-url> --depth 2 --output /tmp/bb-scan.json --format json
```

Run `--help` first. The scanner performs:
- **TLS/SSL analysis** — certificate validity, protocol version, expiry
- **HTTP header audit** — security headers, CORS, information leakage
- **Cookie security** — HttpOnly, Secure, SameSite flags
- **Path discovery** — probes 50+ common paths for sensitive files (.env, .git, admin panels, API docs, backups)
- **Crawling** — discovers links, forms, scripts, input fields
- **Active testing** — injects SQLi, XSS, traversal, SSTI probes into discovered parameters

Modes: `--full` (default), `--recon-only` (no active testing), `--headers-only`

### B2: Live Fuzzing — Deep Parameter Testing

After the web scanner identifies endpoints and parameters:

```bash
# Auto-fuzz all parameters found by web_scanner:
python scripts/live_fuzzer.py --scan-file /tmp/bb-scan.json --output /tmp/bb-fuzz.json

# Or fuzz specific endpoints manually:
python scripts/live_fuzzer.py --url http://target/search --params "q=test" --method GET
python scripts/live_fuzzer.py --url http://target/login --params "user=admin&pass=test" --method POST
```

The live fuzzer sends actual HTTP requests with attack payloads:
- **SQL Injection** — error-based, union-based, time-based (measures response delay)
- **XSS** — reflected, DOM-based, filter bypass
- **Command Injection** — with unique markers to confirm execution
- **SSRF** — internal IPs, cloud metadata endpoints
- **Path Traversal** — Unix/Windows paths with encoding variations
- **SSTI** — arithmetic probes (7*7=49) for template injection
- **Boundary values** — empty strings, max int, null bytes, oversized input

Each finding includes: endpoint, parameter, method, payload used, HTTP status, response time, and fix.

### B3: Manual Black-Box Assessment

After automated scans, manually assess:

1. **Authentication flows** — test login with common credentials, check for account lockout, test password reset
2. **Session management** — check if session regenerates after login, test session timeout
3. **API endpoints** — if Swagger/OpenAPI was discovered, test each endpoint for authorization
4. **GraphQL** — if detected, test introspection, nested queries, alias batching
5. **WebSocket** — if detected, test for cross-site WebSocket hijacking

Read `references/advanced-attacks.md` for detailed techniques for each.

---

## WHITE-BOX WORKFLOW (Source Code Analysis)

When the user provides source code or a file path.

### W1: Reconnaissance & Scope

Map the attack surface before scanning:

```
# Find endpoints, inputs, database queries, file operations, crypto, configs
Grep: pattern="@(app\.(get|post|put|delete)|router\.(get|post|put|delete)|@RequestMapping)"
Grep: pattern="(request\.(body|params|query|headers|cookies)|req\.(body|params|query)|\$_(GET|POST|REQUEST))"
Grep: pattern="(execute|query|raw|cursor\.execute|prepare\()"
Grep: pattern="(jwt|token|password|hash|encrypt|secret|apikey|api_key)"
Glob: pattern="**/{.env*,config.*,docker-compose*,Dockerfile,*.yaml,*.yml}"
```

### W2: Static Analysis (65+ Patterns)

```bash
python scripts/static_analyzer.py --target <path> --output /tmp/wb-static.json
```

Scans for vulnerability patterns across Python, JavaScript, Java, PHP, Go, C#, Ruby + generic patterns. Detects: SQL injection, XSS, command injection, deserialization, weak crypto, hardcoded secrets, SSRF, path traversal, and more.

### W3: Taint Tracking (False Positive Reduction)

**This is the key improvement over basic static analysis.** The taint tracker traces user input from source to sink:

```bash
python scripts/taint_tracker.py --target <path> --output /tmp/wb-taint.json
```

It identifies:
- **Sources** — where user input enters (request.body, req.params, $_GET, etc.)
- **Sinks** — where dangerous operations happen (cursor.execute, innerHTML, os.system, etc.)
- **Sanitizers** — what breaks the taint chain (parameterized queries, escape functions, etc.)

Only paths where user input reaches a dangerous sink **without sanitization** are reported as findings. This eliminates false positives where the static analyzer flags a pattern that is actually safe in context.

### W4: Dependency Audit (Live CVE Lookup)

```bash
# Local database check (fast, offline):
python scripts/dependency_checker.py --target <path> --output /tmp/wb-deps.json

# Live CVE lookup (real-time, comprehensive):
python scripts/cve_lookup.py --scan-deps <path> --output /tmp/wb-cve-live.json

# Check specific package:
python scripts/cve_lookup.py --package lodash --version 4.17.20 --ecosystem npm

# Look up specific CVE:
python scripts/cve_lookup.py --cve CVE-2021-44228
```

The live lookup queries **OSV.dev** (Google, no rate limit) and **NVD** (NIST, rate-limited) APIs in real-time. Set `NVD_API_KEY` environment variable for higher NVD rate limits.

### W5: Configuration & Infrastructure Review

```bash
python scripts/config_auditor.py --target <path> --output /tmp/wb-config.json
```

Scans: .env files, Dockerfiles, docker-compose, CI/CD pipelines, nginx configs, .gitignore. Read `references/hardening.md` for comprehensive checklists.

### W6: Advanced Attack Simulation

```bash
# Generate context-aware fuzz plan from code analysis:
python scripts/fuzzer.py --target <path> --mode auto --output /tmp/wb-fuzz.json

# Auth-specific test cases:
python scripts/fuzzer.py --target <path> --mode auth --output /tmp/wb-auth-tests.json
```

Also manually assess: authentication logic, authorization logic, business logic flaws, error handling, data exposure. Read `references/owasp-top10.md` for per-language detection patterns, `references/attack-patterns.md` for exploit techniques, `references/advanced-attacks.md` for MFA/OAuth2/JWT/microservices/container attacks.

---

## COMBINED MODE

When both source code and a running URL are available, run both workflows and cross-reference:

1. Run white-box static analysis → finds potential vulnerabilities in code
2. Run black-box scanner against URL → finds exploitable vulnerabilities
3. **Cross-reference**: a code vulnerability that is also exploitable via HTTP = **confirmed critical**
4. A code vulnerability NOT exploitable via HTTP = lower priority (defense in depth)
5. A black-box finding NOT visible in code = investigate (might be in dependencies/infrastructure)

---

## REPORT GENERATION

### Generate Unified Report

```bash
# Aggregates ALL scan results (white-box + black-box) into one report:
python scripts/report_generator.py --input /tmp/pentest-results/ --format markdown --output /tmp/final-report.md

# CI/CD security gate:
python scripts/report_generator.py --input /tmp/pentest-results/ --check-threshold critical
```

### Generate Remediation Playbooks

```bash
python scripts/playbook_generator.py --input /tmp/pentest-results/ --format markdown --output /tmp/playbook.md
```

Generates step-by-step fix instructions with before/after code examples for each vulnerability type. Read `references/playbooks.md` for the full playbook library.

### Compare Between Versions

```bash
python scripts/diff_analyzer.py --baseline old-results.json --current new-results.json --format markdown
```

Tracks new, resolved, persistent, and moved vulnerabilities. Reports risk score trend.

### Report Structure

Every report includes:
- **Executive summary** with risk score, severity breakdown, top 3 actions
- **Findings** with severity, category, CWE, location/endpoint, evidence (payload/code), PoC, fix
- **Dependency vulnerabilities** with CVE IDs and fix versions
- **Configuration issues** with remediation
- **Recommendations** prioritized by risk reduction impact

---

## CI/CD INTEGRATION

```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Static Analysis
        run: python scripts/static_analyzer.py --target . --output results/static.json
      - name: Taint Tracking
        run: python scripts/taint_tracker.py --target . --output results/taint.json
      - name: Dependency Check
        run: python scripts/dependency_checker.py --target . --output results/deps.json
      - name: Live CVE Lookup
        run: python scripts/cve_lookup.py --scan-deps . --output results/cve-live.json
        continue-on-error: true
      - name: Config Audit
        run: python scripts/config_auditor.py --target . --output results/config.json
      - name: Generate Report
        run: python scripts/report_generator.py --input results/ --format markdown --output results/report.md
      - name: Generate Playbooks
        run: python scripts/playbook_generator.py --input results/ --format markdown --output results/playbook.md
      - name: Security Gate
        run: python scripts/report_generator.py --input results/ --check-threshold critical
```

---

## REFERENCE FILES

| Reference | Content | When to Read |
|-----------|---------|-------------|
| `references/owasp-top10.md` | Detection patterns for all 10 OWASP categories, per language | W2 — static analysis |
| `references/attack-patterns.md` | 12 attack types with PoC payloads and remediation | W6/B5 — attack simulation |
| `references/api-security.md` | JWT, OAuth2, GraphQL, REST, session testing | Auth/API testing |
| `references/hardening.md` | Server, DB, app, container, cloud hardening checklists | W5 — config review |
| `references/advanced-attacks.md` | MFA bypass, privilege escalation, microservices, K8s, WebSocket | Advanced simulation |
| `references/playbooks.md` | 10 remediation playbooks with step-by-step code fixes | Report generation |

## SCRIPT REFERENCE

| Script | Mode | Purpose |
|--------|------|---------|
| `scripts/web_scanner.py` | **Black-Box** | Full HTTP scan: TLS, headers, cookies, path discovery, crawl, active testing |
| `scripts/live_fuzzer.py` | **Black-Box** | Send real attack payloads to endpoints, analyze responses |
| `scripts/static_analyzer.py` | White-Box | 65+ vulnerability patterns across 7 languages |
| `scripts/taint_tracker.py` | White-Box | Trace user input source→sink, eliminate false positives |
| `scripts/cve_lookup.py` | White-Box | Real-time CVE lookup via NVD + OSV.dev APIs |
| `scripts/dependency_checker.py` | White-Box | Local CVE database check for dependencies |
| `scripts/config_auditor.py` | White-Box | Env, Docker, CI/CD, nginx configuration audit |
| `scripts/fuzzer.py` | White-Box | Context-aware payload generation from code analysis |
| `scripts/report_generator.py` | Both | Aggregate findings into professional audit report |
| `scripts/playbook_generator.py` | Both | Generate step-by-step remediation playbooks |
| `scripts/diff_analyzer.py` | Both | Compare reports between versions, track trends |

All scripts support `--help`. Run that first before reading source code.
