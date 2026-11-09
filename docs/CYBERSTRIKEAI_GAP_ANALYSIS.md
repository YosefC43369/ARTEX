# CyberStrikeAI → ARTEX Gap Analysis

Comparison of **CyberStrikeAI** (`github.com/AIPentest/CyberStrikeAI`, a large Go
platform, ~825 Go files) against **ARTEX** (this repo, Python/Flask), identifying
capabilities CyberStrikeAI has that ARTEX lacked, and what was added here as a
result.

> The two projects are different stacks, so this is a **conceptual** port, not a
> code port. Features were re-implemented in ARTEX's Python idiom inside the
> existing `penetration_testing/` subsystem, keeping ARTEX's fail-closed,
> non-destructive, evidence-validated design.

## Feature comparison

| Capability | CyberStrikeAI | ARTEX (before) | ARTEX (after this change) |
|---|:--:|:--:|:--:|
| Agentic autonomous loop | ✅ | ✅ (`orchestrator`) | ✅ |
| Scope / target authorization | ✅ | ✅ (`scope_manager`) | ✅ |
| Module/tool bridge | ✅ (MCP) | ✅ (`module_bridge`) | ✅ |
| Evidence + integrity | ✅ | ✅ (`evidence_store`) | ✅ |
| Multi-format reporting | ✅ | ✅ (`reporter`) | ✅ |
| **Role-based testing** | ✅ (`roles/*.yaml`) | ❌ | ✅ `roles.py` |
| **Knowledge base** | ✅ (`knowledge_base/`) | ❌ | ✅ `knowledge/` + `knowledge_base.py` |
| **Human-in-the-loop approval** | ✅ (HITL) | ❌ | ✅ `security/approval.py` |
| **Asset management** (normalize/dedup) | ✅ | ❌ | ✅ `storage/asset_registry.py` |
| **Vulnerability lifecycle mgmt** | ✅ | partial (findings only) | ✅ `storage/finding_registry.py` |
| External CLI tool recipes (nmap, nuclei…) | ✅ (100+ YAML) | partial (gated modules) | documented as future work |
| Built-in C2 / WebShell / post-exploitation | ✅ | ❌ (by design) | **intentionally excluded** |
| Multi-agent (Plan-Execute / Supervisor) | ✅ | ❌ | documented as future work |
| Platform RBAC / multi-user | ✅ | ❌ | documented as future work |
| Chatbot integrations | ✅ | ❌ | out of scope |

## What was added (files created for ARTEX)

1. **Role-based testing** — `penetration_testing/roles.py`
   A registry of security "roles" (recon-specialist, web-app-tester,
   infra-tester, takeover-hunter, full-spectrum). A role scopes and orders which
   capabilities an engagement runs and supplies a focus hint to the planner.
   Mirrors CyberStrikeAI `roles/*.yaml`, mapped to ARTEX capabilities.

2. **Knowledge base** — `penetration_testing/knowledge/*.json` +
   `penetration_testing/intelligence/knowledge_base.py`
   Curated, retrievable knowledge per vulnerability class (detection hints,
   remediation, references). Enriches findings that lack remediation/references
   and is queryable. Mirrors CyberStrikeAI `knowledge_base/`.

3. **Human-in-the-loop approval** — `penetration_testing/security/approval.py`
   A governance gate: capabilities flagged as high-impact require explicit
   operator approval before the executor will run them. Pending approvals are
   surfaced via the API; the engagement can be resumed once approved. Mirrors
   CyberStrikeAI's HITL approval modes.

4. **Asset + Vulnerability management** — `penetration_testing/storage/`
   - `asset_registry.py`: normalizes and de-duplicates discovered hosts, IPs,
     ports and services across engagements.
   - `finding_registry.py`: vulnerability lifecycle (open → triaged → confirmed
     → resolved / accepted), cross-engagement de-duplication, filtering, stats.

## Deliberately excluded

CyberStrikeAI ships offensive post-exploitation (C2, WebShell management,
Metasploit/mimikatz/impacket recipes). These are intentionally **not** ported:
ARTEX is a non-destructive, scope-enforced assessment platform, and its own
engineering directive keeps high-impact actions out of the default build. The
added features above are all passive/governance/organizational — they make
ARTEX more capable without expanding its destructive surface.
