# Security Pentest Skill — Documentacao Completa

## Visao Geral

Skill de penetration testing semi-autonoma com operacao dual-mode:
- **White-Box**: analise de codigo-fonte (7 linguagens, 65+ padroes, taint tracking, CVE ao vivo)
- **Black-Box**: teste de aplicacoes via URL (requests HTTP reais, fuzzing, crawling, headers)

**Total: 9.672 linhas de codigo | 11 scripts | 6 referencias | 17 arquivos**

---

## Arquitetura

```
                         ENTRADA DO USUARIO
                                |
                 +--------------+--------------+
                 |                             |
            URL / Website                 Codigo-Fonte
                 |                             |
          BLACK-BOX MODE                WHITE-BOX MODE
                 |                             |
    +------------+------------+    +-----------+-----------+
    | web_scanner.py          |    | static_analyzer.py    |
    |   TLS/SSL               |    |   65+ padroes         |
    |   Headers/Cookies       |    |   7 linguagens        |
    |   Path Discovery (50+)  |    |                       |
    |   Crawling              |    | taint_tracker.py      |
    |   SQLi/XSS/SSRF test   |    |   Source -> Sink      |
    |                         |    |   Elimina falsos +    |
    | live_fuzzer.py          |    |                       |
    |   Payloads HTTP reais   |    | cve_lookup.py         |
    |   Analise de resposta   |    |   OSV.dev + NVD API   |
    |   Time-based detection  |    |                       |
    +------------+------------+    | dependency_checker.py  |
                 |                 |   8 package managers   |
                 |                 |                       |
                 |                 | config_auditor.py     |
                 |                 |   .env, Docker, CI/CD |
                 |                 |                       |
                 |                 | fuzzer.py             |
                 |                 |   Payloads por contexto|
                 |                 +-----------+-----------+
                 |                             |
                 +-------------+---------------+
                               |
                    +----------+----------+
                    | report_generator.py  |
                    | playbook_generator.py|
                    | diff_analyzer.py     |
                    +---------------------+
```

---

## Scripts — Funcoes Detalhadas

### 1. `web_scanner.py` (911 linhas) — BLACK-BOX

**O que faz:** Scanner HTTP completo que faz requests reais contra uma URL.

| Funcionalidade | Detalhe |
|---|---|
| Analise TLS/SSL | Verifica versao do protocolo (TLS 1.0/1.1 = vuln), validade do certificado, dias ate expirar |
| Headers de seguranca | Verifica 7 headers obrigatorios: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection |
| Deteccao de vazamento | Identifica headers que revelam tecnologia: Server, X-Powered-By, X-AspNet-Version |
| Analise de CORS | Detecta wildcard origin, wildcard + credentials (critico), origin reflection |
| Seguranca de cookies | Verifica HttpOnly, Secure, SameSite em cookies de sessao |
| Path discovery | Probe 50+ caminhos comuns: .env, .git, admin, swagger, phpinfo, backups, actuator, debug |
| Crawling | Navega paginas, extrai links, formularios, scripts, inputs — respeita same-origin |
| Teste de SQLi | Injeta 5 payloads em cada parametro, detecta por erro SQL na resposta ou status 500 |
| Teste de XSS | Injeta payloads com marcador unico, verifica se reflete sem encoding |
| Teste de Path Traversal | Tenta ../../../etc/passwd, verifica conteudo de arquivo na resposta |
| Teste de SSTI | Injeta {{7*7}}, ${7*7}, verifica se "49" aparece na resposta |
| Deteccao de CSRF | Verifica se formularios POST tem token CSRF |

**Modos:**
- `--full` — scan completo (padrao)
- `--recon-only` — so reconhecimento, sem testes ativos
- `--headers-only` — so TLS + headers

**Exemplo real testado:**
```
python web_scanner.py --url https://example.com --headers-only
-> Detectou: Missing HSTS (high), Missing CSP (high), Missing X-Frame-Options (medium)...
-> Risk Score: 42/100
```

---

### 2. `live_fuzzer.py` (455 linhas) — BLACK-BOX

**O que faz:** Envia payloads de ataque reais via HTTP e analisa as respostas.

| Funcionalidade | Detalhe |
|---|---|
| SQL Injection | 13 payloads (error-based, union, time-based). Detecta por: erro SQL na resposta, status 500, delay >2.5s |
| XSS Reflected | 8 payloads. Detecta por: reflexao do payload sem encoding no body |
| Command Injection | 6 payloads com marcador unico (CMDI_MARKER_82391). Detecta por: marcador na resposta |
| SSRF | 7 payloads (localhost, cloud metadata). Detecta por: conteudo interno na resposta |
| Path Traversal | 6 payloads (Unix/Windows, encoding). Detecta por: conteudo de arquivo sistema |
| SSTI | 5 payloads ({{7*7}}, ${7*7}). Detecta por: "49" na resposta |
| Header Injection | 3 payloads CRLF. Detecta por: header injetado na resposta |
| Boundary Values | 8 valores limite (vazio, null, MAX_INT, 10000 chars). Detecta por: crash (500) |
| Baseline comparison | Primeiro faz request normal, depois compara status/tamanho/tempo das respostas fuzzed |
| Auto-fuzz | Le resultados do web_scanner e fuzza automaticamente todos os parametros descobertos |

**Deteccao inteligente:**
- Compara cada resposta com o baseline (request sem payload)
- Time-based: se resposta demora >2.5s alem do baseline = possivel blind SQLi
- Error-based: se status muda para 500 = possivel injecao
- Marker-based: se marcador unico aparece = confirmado

---

### 3. `static_analyzer.py` (533 linhas) — WHITE-BOX

**O que faz:** Scanner de padroes regex para vulnerabilidades em codigo-fonte.

| Linguagem | Padroes | Tipos de Vulnerabilidade |
|---|---|---|
| Python | 17 | SQLi, CMDi, eval, exec, os.system, pickle, YAML, MD5, SHA1, hardcoded secrets, SSL bypass, debug mode, SSRF, XSS, path traversal |
| JavaScript | 14 | eval, innerHTML, document.write, dangerouslySetInnerHTML, child_process.exec, SQL concat, Math.random, hardcoded secrets, JWT sem algoritmo, CORS wildcard, prototype pollution, MemoryStore |
| Java | 6 | SQL concat, Runtime.exec, ObjectInputStream, XXE, MD5/SHA1, log injection |
| PHP | 7 | SQL injection, command injection, eval, unserialize, XSS echo, file inclusion, display_errors |
| Go | 4 | SQL concat, command exec, InsecureSkipVerify, math/rand |
| C# | 4 | SQL concat, Process.Start, BinaryFormatter, Html.Raw |
| Ruby | 4 | SQL interpolation, system/exec, Marshal.load, html_safe |
| Generico | 8 | Hardcoded password, API key, private key, AWS key, TODO security, HTTP URL, internal IP, connection string |

**Total: 65 padroes unicos cobrindo 24 CWEs**

---

### 4. `taint_tracker.py` (456 linhas) — WHITE-BOX

**O que faz:** Traca o fluxo de dados do usuario (source) ate operacoes perigosas (sink), verificando se existe sanitizacao no caminho. Elimina falsos positivos.

| Componente | Linguagens | Exemplos |
|---|---|---|
| **Sources (entrada de dados)** | 7 linguagens | `request.body`, `req.params`, `$_GET`, `getParameter()`, `r.FormValue()`, `params[:]`, `Request.Query[]` |
| **Sinks (operacoes perigosas)** | 6 categorias | SQL execution, XSS output, command execution, file operations, HTTP requests (SSRF), deserialization |
| **Sanitizers (o que protege)** | 5 categorias | Parameterized queries, escape functions, shlex.quote, path normalization, URL validation |

**Logica:**
1. Encontra todas as sources no arquivo
2. Encontra todos os sinks no arquivo
3. Para cada par source-sink no mesmo arquivo (dentro de 50 linhas):
   - Verifica se a variavel do source aparece no codigo do sink
   - Se sim, verifica se existe um sanitizer entre eles
   - Se nao existe sanitizer = **vulnerabilidade confirmada**
   - Se existe sanitizer = **falso positivo eliminado**

**Resultado pratico:** Reduz significativamente o ruido do static_analyzer, reportando apenas os caminhos realmente exploitaveis.

---

### 5. `cve_lookup.py` (407 linhas) — WHITE-BOX

**O que faz:** Consulta bancos de dados de vulnerabilidades em tempo real.

| API | Rate Limit | Cobertura |
|---|---|---|
| **OSV.dev** (Google) | Sem limite | npm, PyPI, Maven, Go, crates.io, RubyGems, Packagist, NuGet |
| **NVD** (NIST) | 5 req/30s (sem key), 50 req/30s (com key) | Todas as CVEs registradas |

| Funcionalidade | Detalhe |
|---|---|
| Lookup por pacote | `--package lodash --version 4.17.20 --ecosystem npm` |
| Lookup por CVE | `--cve CVE-2021-44228` |
| Scan de projeto | `--scan-deps ./myproject` — detecta package.json, requirements.txt, go.mod, composer.json |
| Parse de resposta | Extrai: CVE ID, descricao, CVSS score, severidade, versao de correcao, referencias |
| Fallback | Tenta OSV primeiro (sem rate limit), se nao achar tenta NVD |

---

### 6. `dependency_checker.py` (471 linhas) — WHITE-BOX

**O que faz:** Verifica dependencias contra base local de CVEs conhecidas (funciona offline).

| Package Manager | Arquivo Detectado | Vulnerabilidades na Base |
|---|---|---|
| npm | package.json, package-lock.json, yarn.lock | lodash, express, axios, jsonwebtoken, minimist, node-fetch, qs, semver, shell-quote, tar |
| pip | requirements.txt, Pipfile, pyproject.toml | django, flask, requests, pyyaml, pillow, cryptography, jinja2, sqlalchemy, urllib3, werkzeug |
| composer | composer.json | laravel, symfony, guzzle |
| maven | pom.xml | log4j, jackson, spring |
| go | go.mod | (parse basico) |
| cargo | Cargo.toml | (detecta presenca) |
| gems | Gemfile | (detecta presenca) |
| nuget | *.csproj | (detecta presenca) |

Tambem detecta **versoes nao fixadas** (^, ~, >=, *) como risco de supply chain.

---

### 7. `config_auditor.py` (479 linhas) — WHITE-BOX

**O que faz:** Escaneia configuracoes e infraestrutura.

| Area | Regras | O que Detecta |
|---|---|---|
| .env files | 7 regras | DEBUG=true, secret key fraca, DB password, API keys, database URL com credentials, CORS *, SSL disabled |
| Dockerfile | 7 regras | Container root, :latest tag, COPY de secrets, portas sensiveis, ADD vs COPY, privileged mode, Docker socket |
| CI/CD | 4 regras | Actions nao fixadas (@master), secrets hardcoded, pull_request_target, script injection |
| .gitignore | 2 regras | Ausencia de .gitignore, falta de .env/*.pem/*.key no gitignore |
| nginx | 5 regras | Headers de seguranca faltando, server_tokens, TLS fraco |
| Exposed secrets | 9 padroes | .env, id_rsa, *.pem, credentials.json, service-account, .npmrc, .pypirc |

---

### 8. `fuzzer.py` (843 linhas) — WHITE-BOX

**O que faz:** Analisa o codigo-fonte para descobrir endpoints, inputs e mecanismos de auth, e gera planos de fuzzing com payloads contextuais.

| Modo | O que Descobre | Payloads Gerados |
|---|---|---|
| `auto` | Tudo | Todos os payloads relevantes |
| `api` | Rotas/endpoints no codigo | SQLi, XSS, NoSQL injection, mass assignment, boundary values, SSRF, path traversal por endpoint |
| `input` | Campos de input (request.body, $_GET, etc) | Payloads especificos por tipo de campo (email, URL, ID, nome, senha, arquivo, comando) |
| `file` | Pontos de file upload | 10 payloads de upload (PHP exec, SVG XSS, path traversal em filename, double extension, null byte, .htaccess) |
| `auth` | JWT, MFA, OAuth, sessions | 27 cenarios de teste: MFA bypass (4), session attacks (3), JWT attacks (4), privilege escalation (4), OAuth2 (3) |

**Payload library:** 158+ payloads individuais + 73 boundary values

---

### 9. `report_generator.py` (400 linhas) — AMBOS

**O que faz:** Agrega resultados de TODOS os scanners em um relatorio profissional unificado.

| Funcionalidade | Detalhe |
|---|---|
| Agregacao | Le todos os JSONs de uma pasta e combina findings |
| Risk Score | Pontuacao 0-100 (critical=25pts, high=15, medium=5, low=1) |
| Executive Summary | Total, breakdown por severidade, top 3 acoes |
| Findings detalhados | ID, severidade, categoria, CWE, localizacao, evidencia, fix |
| Recomendacoes | Priorizadas por severidade (P0 critical, P1 high, P2 medium) |
| CI/CD Gate | `--check-threshold critical` — retorna exit code 1 se houver vulns acima do threshold |
| Formatos | Markdown (legivel), JSON (machine-parseable) |

---

### 10. `playbook_generator.py` (553 linhas) — AMBOS

**O que faz:** Gera playbooks de remediacao passo-a-passo a partir dos findings.

| CWE | Playbook | Prioridade | Linguagens com Exemplo |
|---|---|---|---|
| CWE-89 | SQL Injection | P0 Imediato | Python, JS, Java, PHP, Go, C# |
| CWE-79 | XSS | P1 7 dias | Python, JS, nginx (CSP) |
| CWE-78 | Command Injection | P0 Imediato | Python, JS, PHP |
| CWE-798 | Hardcoded Credentials | P0 Imediato | Python, JS |
| CWE-502 | Deserialization | P0 Imediato | Python, Java, PHP |
| CWE-918 | SSRF | P1 7 dias | Python |
| CWE-327 | Weak Crypto | P1 7 dias | Python, JS |
| CWE-295 | SSL Bypass | P1 7 dias | Python, JS |
| CWE-611 | XXE | P0 Imediato | Python, Java |
| CWE-330 | Weak Random | P1 7 dias | Python, JS |
| CWE-22 | Path Traversal | P0 Imediato | Python, JS |

Cada playbook inclui: titulo, prioridade, esforco estimado, steps numerados, codigo before/after, comandos de verificacao, prevencao.

---

### 11. `diff_analyzer.py` (372 linhas) — AMBOS

**O que faz:** Compara relatorios de seguranca entre versoes.

| Funcionalidade | Detalhe |
|---|---|
| Fingerprinting | Cria fingerprint unico por finding (ID + nome + arquivo + CWE) |
| Fingerprint flexivel | Ignora numero de linha para detectar findings que mudaram de posicao |
| Classificacao | **New** (introduzido), **Resolved** (corrigido), **Persistent** (ainda presente), **Moved** (mudou de lugar) |
| Risk trending | Score baseline vs current, delta, trend (improved/degraded/unchanged) |
| Action items | Lista priorizadas: URGENT (new critical), HIGH (new high), OVERDUE (persistent critical) |

---

## Referencias — Conteudo Detalhado

### `owasp-top10.md` (443 linhas)
Padroes de deteccao para cada categoria OWASP 2021, organizados por linguagem:
- A01 Broken Access Control: IDOR, missing auth decorators, path traversal
- A02 Cryptographic Failures: MD5/SHA1, hardcoded keys, weak random, HTTP
- A03 Injection: SQLi, XSS, CMDi (com patterns grep por linguagem)
- A04 Insecure Design: missing rate limiting, race conditions
- A05 Security Misconfiguration: debug mode, default credentials, verbose errors
- A06 Vulnerable Components: dependency checking patterns
- A07 Auth Failures: weak passwords, session issues, JWT problems
- A08 Integrity Failures: deserialization, insecure CI/CD
- A09 Logging Failures: what to log, what not to log
- A10 SSRF: URL fetch patterns, cloud metadata

### `attack-patterns.md` (637 linhas)
12 tipos de ataque com payloads proof-of-concept completos:
SQL Injection (5 subtypes, 25 payloads), XSS (5 contexts), Command Injection, SSRF, XXE, Path Traversal, SSTI, Deserialization, CSRF, HTTP Smuggling, Race Conditions, Fuzzing Methodology

### `api-security.md` (376 linhas)
JWT (algorithm confusion, JWK injection, claim manipulation, brute force), OAuth2 (redirect URI, PKCE, scope escalation), REST (mass assignment, BOLA, rate limiting), GraphQL (introspection, DoS, batching), Session Management, Rate Limiting

### `advanced-attacks.md` (866 linhas)
MFA bypass (5 tecnicas), OAuth2 avancado (4 ataques), JWT deep (4 ataques), Session persistence (3 ataques), Privilege escalation chains (3 tipos + chains), Microservices (4 vetores), Container/K8s (4 vetores), Internal vs External simulation, Network protocol attacks (DNS rebinding, HTTP desync, WebSocket hijacking), Advanced fuzzing (stateful, context-aware, mutation-based, protocol-level), GraphQL deep (field suggestion, alias batching, nested DoS), WebSocket security

### `hardening.md` (532 linhas)
Nginx (TLS, headers, rate limiting), Apache, PostgreSQL/MySQL/MongoDB, Node.js/Express (helmet, rate limit, session), Django/Flask, Docker (Dockerfile + Compose), Kubernetes (RBAC, NetworkPolicy), Cloud (AWS/GCP/Azure), Supply chain, Secrets management, Security headers reference table

### `playbooks.md` (624 linhas)
10 playbooks completos: SQLi remediation, XSS remediation, Auth hardening, API security, Secrets rotation emergency, Dependency response, Container hardening, CI/CD security, Incident response, Security monitoring setup

---

## Numeros Consolidados

| Metrica | Valor |
|---|---|
| Total de linhas de codigo | 9.672 |
| Scripts executaveis | 11 |
| Documentos de referencia | 6 |
| Padroes de vulnerabilidade (static) | 65 |
| Linguagens suportadas (white-box) | 7 (Python, JS, Java, PHP, Go, C#, Ruby) + generico |
| CWEs cobertos | 24 unicos |
| Payloads de ataque (fuzzer) | 158+ individuais |
| Cenarios de auth testing | 27 |
| Paths testados (black-box) | 50+ |
| Package managers suportados | 8 |
| Playbooks de remediacao | 11 (com codigo before/after) |
| Regras de configuracao | 30+ |
| APIs externas integradas | 2 (OSV.dev, NVD/NIST) |
| Categorias de taint tracking | 6 (SQLi, XSS, CMDi, path traversal, SSRF, deserialization) |

---

## Comparacao: Skill vs Pentester Humano

### O que a skill FAZ (e faz bem)

| Capacidade | Nivel | Comparavel a |
|---|---|---|
| Analise estatica de codigo | Excelente | SonarQube, Semgrep, Snyk Code |
| Deteccao de secrets em codigo | Excelente | GitLeaks, TruffleHog, detect-secrets |
| Auditoria de dependencias | Muito Bom | Snyk, npm audit, pip-audit + CVE ao vivo |
| Scan de headers HTTP | Excelente | SecurityHeaders.com, Mozilla Observatory |
| Teste de TLS/SSL | Bom | SSL Labs (versao simplificada) |
| Path discovery | Muito Bom | DirBuster, Gobuster (50+ paths) |
| Crawling e form discovery | Bom | Burp Spider (versao simplificada) |
| SQL Injection testing | Bom | sqlmap (versao basica, sem exploracao completa) |
| XSS detection | Bom | Deteccao de reflexao, similar a XSSHunter basico |
| Fuzzing de parametros | Muito Bom | Burp Intruder (versao simplificada) |
| CSRF detection | Bom | Verifica presenca de token em forms |
| Taint tracking | Bom | Semgrep Pro, CodeQL (versao simplificada) |
| Geracao de relatorios | Excelente | Melhor que muitas tools (estruturado, com playbooks) |
| Playbooks de correcao | Excelente | Unico — maioria das tools so reporta, nao explica como corrigir |
| Comparacao entre versoes | Excelente | Raro em tools — tracking de new/resolved/persistent |
| CI/CD integration | Excelente | Security gate com threshold configuravel |

### O que a skill NAO FAZ (limitacoes reais)

| Capacidade | Status | Por que |
|---|---|---|
| Exploracao real de SQLi (dump database) | Nao faz | So detecta, nao extrai dados |
| Brute force de login | Nao faz | Fora do escopo etico |
| Port scanning / network recon | Nao faz | Sem nmap/masscan |
| Interceptacao de trafego (proxy) | Nao faz | Sem Burp Suite integration |
| Teste com browser real (JS execution) | Nao faz | Sem Playwright/Puppeteer |
| Exploit chains automatizadas | Nao faz | Gera teoria mas nao executa chains |
| Memory corruption / buffer overflow | Nao faz | Sem analise binaria |
| Mobile app testing (APK/IPA) | Nao faz | Fora do escopo |
| Wireless / network attacks | Nao faz | Fora do escopo |
| Social engineering | Nao faz | Fora do escopo |
| Compliance mapping (PCI-DSS, HIPAA) | Nao faz | So seguranca tecnica |
| Threat modeling formal (STRIDE/DREAD) | Parcial | Pode auxiliar mas nao automatiza |
| Business logic flaws | Parcial | Requer raciocinio humano sobre o dominio |
| Race condition exploitation | Parcial | Detecta padroes mas nao testa concorrencia |

### Escala de Substituicao

```
CAPACIDADE                          SKILL    PENTESTER    COBERTURA
                                    COBRE    HUMANO FAZ   DA SKILL

Analise estatica de codigo          █████    █████        100%
Deteccao de secrets                 █████    █████        100%
Auditoria de dependencias           █████    █████        100%
Scan de headers/TLS/cookies         █████    █████        100%
Geracao de relatorio                █████    ████░        125% (playbooks extras)
CI/CD security gate                 █████    ██░░░        250% (automacao)
Comparacao entre versoes            █████    ██░░░        250% (automacao)
Path discovery                      ████░    █████         80%
Crawling de aplicacao               ███░░    █████         60%
Teste de injecao (SQLi/XSS/etc)    ███░░    █████         60%
Fuzzing de parametros               ███░░    █████         60%
Taint analysis                      ███░░    █████         60%
Teste de autenticacao               ██░░░    █████         40%
API testing (GraphQL/REST)          ██░░░    █████         40%
Container/K8s testing               ██░░░    █████         40%
Network reconnaissance              █░░░░    █████         20%
Exploit development                 ░░░░░    █████          0%
Business logic testing              █░░░░    █████         20%
Social engineering                  ░░░░░    █████          0%
```

### Resumo Quantitativo

| Metrica | Valor |
|---|---|
| **Cobertura geral vs pentester** | **~75%** |
| Cobertura em analise de codigo | ~95% |
| Cobertura em black-box testing | ~60% |
| Cobertura em reporting/remediation | ~130% (supera pela automacao) |
| Cobertura em exploitation real | ~20% |
| Cobertura em network/infra | ~25% |

### Quando a Skill SUBSTITUI o Pentester

- Code review de seguranca em PRs
- Auditoria de dependencias e CVEs
- Verificacao de headers e configuracoes
- Security gate em CI/CD pipeline
- Triagem inicial de vulnerabilidades
- Geracao de relatorios e playbooks de correcao
- Comparacao de seguranca entre releases
- Treinamento de devs sobre vulnerabilidades

### Quando PRECISA de Pentester Humano

- Pentest completo com exploracao real
- Bug bounty hunting (criatividade e persistencia)
- Teste de logica de negocio
- Red team / simulacao de adversario
- Analise de rede e infraestrutura
- Mobile / IoT / hardware testing
- Social engineering assessment
- Compliance audit formal (PCI-DSS, SOC2)

### Combinacao Ideal

```
FASE 1: Skill roda automaticamente em CI/CD
        -> Detecta 75% das vulnerabilidades
        -> Gera relatorio + playbooks
        -> Bloqueia deploy se houver critico

FASE 2: Pentester humano foca nos 25% restantes
        -> Business logic
        -> Exploit chains
        -> Network/infra
        -> Criatividade que IA nao tem (ainda)

RESULTADO: Cobertura ~95% com custo reduzido
```

---

## Como Usar — Quick Start

### Modo Black-Box (tenho uma URL)
```bash
# Scan completo
python scripts/web_scanner.py --url https://meusite.com --depth 2 --output /tmp/scan.json

# Fuzzing aprofundado
python scripts/live_fuzzer.py --scan-file /tmp/scan.json --output /tmp/fuzz.json

# Relatorio
python scripts/report_generator.py --input /tmp/ --format markdown --output /tmp/relatorio.md
```

### Modo White-Box (tenho o codigo)
```bash
# Analise estatica
python scripts/static_analyzer.py --target ./meu-projeto --output /tmp/static.json

# Taint tracking (confirma exploitabilidade)
python scripts/taint_tracker.py --target ./meu-projeto --output /tmp/taint.json

# CVE ao vivo
python scripts/cve_lookup.py --scan-deps ./meu-projeto --output /tmp/cve.json

# Config audit
python scripts/config_auditor.py --target ./meu-projeto --output /tmp/config.json

# Relatorio + playbooks
python scripts/report_generator.py --input /tmp/ --format markdown --output /tmp/relatorio.md
python scripts/playbook_generator.py --input /tmp/ --format markdown --output /tmp/playbook.md
```

### Modo Combinado (tenho URL + codigo)
```bash
# White-box
python scripts/static_analyzer.py --target ./codigo --output /tmp/results/static.json
python scripts/taint_tracker.py --target ./codigo --output /tmp/results/taint.json
python scripts/dependency_checker.py --target ./codigo --output /tmp/results/deps.json
python scripts/config_auditor.py --target ./codigo --output /tmp/results/config.json

# Black-box
python scripts/web_scanner.py --url https://meusite.com --depth 2 --output /tmp/results/webscan.json
python scripts/live_fuzzer.py --scan-file /tmp/results/webscan.json --output /tmp/results/fuzz.json

# Unificado
python scripts/report_generator.py --input /tmp/results/ --format markdown --output /tmp/relatorio-completo.md
python scripts/playbook_generator.py --input /tmp/results/ --format markdown --output /tmp/playbook.md
```
