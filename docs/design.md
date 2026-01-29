# Claude Code Plugin Evaluation System
## Design Document v0.1

**Author:** Gruntwork.ai  
**Date:** January 2026  
**Status:** Proposal / First Draft

---

## Executive Summary

The Claude Code plugin ecosystem is experiencing rapid growth without corresponding quality infrastructure. Unlike mature ecosystems (npm, PyPI, VS Code extensions), there is no standardized way to evaluate plugin quality, measure actual usage, compare alternatives, or identify security concerns before installation.

This document proposes a three-layer solution:
1. **Plugin Analyzer** — Static analysis tool for pre-installation evaluation
2. **Runtime Monitor** — Usage tracking and context cost attribution  
3. **Plugin Observatory** — Public aggregator for community-wide intelligence

---

## Part 1: Problem Statement

### The Ecosystem Gap

Claude Code plugins launched in late 2025, introducing a packaging system for distributing commands, agents, skills, hooks, and MCP servers. The system solved distribution but created new problems:

**No Quality Signals**
- No download counts, ratings, or reviews
- No way to compare similar plugins (e.g., Compound-Engineering vs Superpowers)
- No standardized benchmarks for effectiveness
- GitHub stars are the only proxy for popularity

**No Cost Visibility**
- Plugins can silently consume significant context (MCP servers add 5-15K tokens)
- No way to know a plugin's context footprint before installation
- No attribution of token consumption to specific plugins post-installation
- Users discover problems only when they hit context limits

**No Usage Analytics**
- No tracking of which plugin components are actually used
- "Cruft accumulation" — installed plugins sit unused, consuming context
- No data to inform uninstall decisions
- No feedback loop to plugin authors about what's valuable

**No Security Baseline**
- Plugins can include arbitrary shell scripts (hooks)
- MCP servers can have broad permissions
- No audit trail or security review process for community plugins
- "Install at your own risk" with no tooling support

**No Architectural Guidance**
- No way to know if a plugin uses efficient patterns (Skills) vs expensive patterns (MCP servers)
- No detection of redundant functionality across plugins
- No guidance on plugin compatibility or conflicts

### Why This Matters

The plugin ecosystem's value proposition is **leverage** — install once, benefit repeatedly. But without evaluation tools, the actual equation is:

```
Theoretical Value = Σ (capability gains)
Actual Value = Σ (capability gains) - context overhead - security risk - cognitive load of unused features
```

Users cannot currently calculate the right side of this equation. They're making installation decisions with incomplete information, leading to:

- Over-installation (context bloat)
- Under-utilization (paying costs without capturing benefits)  
- Risk exposure (no security visibility)
- Decision paralysis (can't compare alternatives)

### Market Analogies

| Ecosystem | Quality Infrastructure |
|-----------|----------------------|
| npm | Download counts, vulnerability scanning, bundle size analysis, deprecation warnings |
| PyPI | Downloads, security advisories, dependency analysis |
| VS Code | Ratings, reviews, download counts, trending, verified publishers |
| Chrome Extensions | Ratings, reviews, permission warnings, featured selections |
| **Claude Plugins** | GitHub stars only |

The Claude plugin ecosystem is approximately where npm was in 2012 — before `npm audit`, before bundle analyzers, before quality tooling became standard.

---

## Part 2: Solution Architecture

### Layer 1: Plugin Analyzer (Static Analysis)

A tool that evaluates plugins **before installation** by analyzing their repository structure and contents.

#### Core Capabilities

**1.1 Component Inventory**
```
Input: GitHub repo URL or local path
Output: Structured inventory of plugin contents

{
  "name": "compound-engineering",
  "components": {
    "commands": 6,
    "agents": 17,
    "skills": 0,
    "hooks": 0,
    "mcp_servers": 0
  },
  "files_analyzed": 47,
  "total_instruction_tokens": 12847
}
```

**1.2 Context Cost Estimation**

Estimate the token overhead a plugin will add:

| Component Type | Cost Model |
|---------------|------------|
| Commands | ~50-100 tokens per command (description only, on-demand execution) |
| Agents | ~100-300 tokens per agent (description in context, body on invocation) |
| Skills | ~20-50 tokens per skill (name + description only until invoked) |
| MCP Servers | **~500-2000 tokens per server** (all tool definitions always in context) |
| Hooks | 0 tokens (execute outside context) |

```
{
  "context_cost": {
    "baseline_overhead": 2400,
    "on_demand_max": 8500,
    "cost_rating": "moderate",
    "primary_driver": "17 agent descriptions"
  }
}
```

**1.3 Architecture Assessment**

Evaluate design choices:

```
{
  "architecture": {
    "pattern": "agent-heavy",
    "efficiency_notes": [
      "Uses agents for specialized review (parallel execution benefit)",
      "No MCP servers (avoids always-on context cost)",
      "Could convert 5 agents to skills for context savings"
    ],
    "recommendations": [
      "Consider skill-based approach for infrequently-used reviewers"
    ]
  }
}
```

**1.4 Security Scan**

Flag potential concerns:

```
{
  "security": {
    "risk_level": "low",
    "findings": [
      {
        "type": "hook_shell_execution",
        "file": "hooks/pre-commit.sh",
        "severity": "info",
        "note": "Hook executes shell commands; review before trusting"
      }
    ],
    "mcp_permissions": [],
    "external_dependencies": ["gh CLI"]
  }
}
```

**1.5 Overlap Detection**

Compare against installed plugins and built-in capabilities:

```
{
  "overlap": {
    "with_builtin": [
      "security-review command overlaps with /security-review"
    ],
    "with_installed": [
      "code-review agents overlap with superpowers reviewing workflow"
    ],
    "redundancy_cost": "~3000 tokens of duplicate capability"
  }
}
```

#### Implementation Approach

```
plugin-analyzer/
├── src/
│   ├── inventory.py          # Parse plugin structure
│   ├── tokenizer.py          # Estimate token costs
│   ├── architecture.py       # Assess design patterns
│   ├── security.py           # Security scanning
│   ├── overlap.py            # Redundancy detection
│   └── reporter.py           # Generate reports
├── rules/
│   ├── security_patterns.yaml
│   ├── efficiency_heuristics.yaml
│   └── known_overlaps.yaml
└── cli.py                    # Command-line interface
```

**Usage:**
```bash
# Analyze before installing
npx plugin-analyzer https://github.com/EveryInc/compound-engineering-plugin

# Compare two plugins
npx plugin-analyzer compare \
  https://github.com/EveryInc/compound-engineering-plugin \
  https://github.com/obra/superpowers
```

---

### Layer 2: Runtime Monitor (Usage Analytics)

A daemon or hook that tracks actual plugin usage over time.

#### Core Capabilities

**2.1 Command/Skill Invocation Tracking**

```
{
  "period": "2025-01-06 to 2025-01-13",
  "invocations": {
    "compound-engineering:plan": 12,
    "compound-engineering:review": 8,
    "compound-engineering:work": 3,
    "compound-engineering:triage": 0,
    "compound-engineering:resolve_todo_parallel": 0,
    "compound-engineering:generate_command": 0
  }
}
```

**2.2 Context Attribution**

Attribute token consumption to specific plugins:

```
{
  "context_attribution": {
    "baseline": 5200,
    "compound-engineering": {
      "static_overhead": 2400,
      "invocation_cost": 4800,
      "total": 7200
    },
    "superpowers": {
      "static_overhead": 1800,
      "invocation_cost": 2100,
      "total": 3900
    }
  }
}
```

**2.3 Utilization Analysis**

Identify underused plugins:

```
{
  "utilization": {
    "compound-engineering": {
      "components_available": 23,
      "components_used": 8,
      "utilization_rate": 0.35,
      "unused_components": [
        "triage",
        "resolve_todo_parallel", 
        "generate_command",
        "kieran-python-reviewer",
        "dhh-rails-reviewer",
        // ... 
      ],
      "recommendation": "Consider disabling unused agents to reduce context overhead"
    }
  }
}
```

**2.4 ROI Calculation**

```
{
  "roi_estimate": {
    "compound-engineering": {
      "context_cost_tokens": 7200,
      "estimated_monthly_cost": "$2.40",
      "time_saved_estimate": "4-6 hours (based on 12 plan generations)",
      "verdict": "positive_roi"
    }
  }
}
```

#### Implementation Approach

**Option A: Hook-Based (Non-invasive)**

Add a SessionStart hook that logs to a local SQLite database:

```python
# hooks/usage-tracker.py
import sqlite3
import json
from datetime import datetime

def log_session_start(context):
    """Log loaded plugins and their components"""
    db = sqlite3.connect("~/.claude/plugin-usage.db")
    db.execute("""
        INSERT INTO sessions (timestamp, plugins_loaded, context_snapshot)
        VALUES (?, ?, ?)
    """, (datetime.now(), json.dumps(context['plugins']), context['tokens']))
```

**Option B: OpenTelemetry Integration**

Leverage Claude Code's existing OTel support to capture tool invocations:

```yaml
# Configure OTEL to export to local collector
CLAUDE_CODE_ENABLE_TELEMETRY: 1
OTEL_LOGS_EXPORTER: otlp
OTEL_EXPORTER_OTLP_ENDPOINT: http://localhost:4317
```

Then parse `claude_code.tool_result` events to attribute usage to plugins.

**Option C: Transcript Analysis**

Parse the local JSONL transcripts (what `ccusage` does) and correlate command invocations with installed plugins.

---

### Layer 3: Plugin Observatory (Public Aggregator)

A web service that aggregates anonymized data from consenting users to provide community-wide plugin intelligence.

#### Core Capabilities

**3.1 Plugin Directory**

```
GET /api/plugins

[
  {
    "name": "superpowers",
    "repo": "obra/superpowers",
    "version": "1.4.0",
    "stars": 12300,
    "installs_estimated": 2400,
    "avg_utilization": 0.62,
    "context_cost": {
      "baseline": 1800,
      "typical_session": 3200
    },
    "categories": ["workflow", "tdd", "planning"],
    "similar_plugins": ["compound-engineering", "ralph-loop"]
  }
]
```

**3.2 Comparative Analysis**

```
GET /api/compare?plugins=compound-engineering,superpowers

{
  "comparison": {
    "philosophy": {
      "compound-engineering": "Parallel specialist agents, quality compounding",
      "superpowers": "Structured workflows, strict TDD"
    },
    "context_cost": {
      "compound-engineering": 2400,
      "superpowers": 1800,
      "winner": "superpowers"
    },
    "community_adoption": {
      "compound-engineering": 3200,
      "superpowers": 12300,
      "winner": "superpowers"
    },
    "utilization_rate": {
      "compound-engineering": 0.48,
      "superpowers": 0.62,
      "winner": "superpowers"
    },
    "feature_overlap": 0.35,
    "recommendation": "Choose based on workflow preference; superpowers for TDD-first, compound-engineering for review-heavy workflows"
  }
}
```

**3.3 Trending & Discovery**

```
GET /api/trending?period=week

[
  {
    "plugin": "superpowers",
    "trend": "+340 installs",
    "reason": "Featured in Anthropic engineering blog"
  },
  {
    "plugin": "frontend-design",
    "trend": "+180 installs", 
    "reason": "Official Anthropic plugin"
  }
]
```

**3.4 Security Advisories**

```
GET /api/advisories

[
  {
    "plugin": "example-vulnerable-plugin",
    "severity": "high",
    "description": "Hook executes unvalidated user input",
    "affected_versions": ["< 1.2.0"],
    "recommendation": "Upgrade to 1.2.0 or uninstall"
  }
]
```

**3.5 Quality Scores**

Composite score based on multiple signals:

```
{
  "quality_score": {
    "overall": 8.2,
    "components": {
      "adoption": 9.0,
      "utilization": 7.5,
      "efficiency": 8.0,
      "maintenance": 8.5,
      "security": 8.0
    }
  }
}
```

#### Data Collection Model

**Opt-in Telemetry:**
```
# User enables Observatory contribution
PLUGIN_OBSERVATORY_CONTRIBUTE=1
PLUGIN_OBSERVATORY_ENDPOINT=https://observatory.gruntwork.ai/ingest
```

**Data Transmitted (anonymized):**
```json
{
  "user_id_hash": "sha256(user_id + salt)",
  "timestamp": "2025-01-13T14:30:00Z",
  "plugins_installed": ["superpowers", "compound-engineering"],
  "invocations": {
    "superpowers:brainstorm": 3,
    "compound-engineering:plan": 1
  },
  "context_snapshot": {
    "total_tokens": 45000,
    "plugin_attributed": 8200
  }
}
```

**Privacy Guarantees:**
- No code, prompts, or file contents transmitted
- User IDs hashed and salted
- Aggregation requires minimum sample sizes
- Users can request data deletion

---

## Part 3: Implementation Roadmap

### Phase 1: Plugin Analyzer (Weeks 1-4)

**Deliverables:**
- CLI tool for static plugin analysis
- GitHub repo URL → structured report
- Basic security scanning
- Context cost estimation

**Success Criteria:**
- Can analyze any public plugin repo
- Produces actionable recommendations
- Identifies MCP vs Skills architecture choices

### Phase 2: Runtime Monitor (Weeks 5-8)

**Deliverables:**
- Local usage tracking (hook or transcript analysis)
- SQLite-based storage
- CLI for usage reports
- Utilization and ROI calculations

**Success Criteria:**
- Tracks command invocations per plugin
- Identifies unused components
- Provides clear uninstall recommendations

### Phase 3: Plugin Observatory (Weeks 9-16)

**Deliverables:**
- Web service for aggregated data
- Public API for plugin intelligence
- Web UI for browsing and comparison
- Opt-in telemetry client

**Success Criteria:**
- 100+ plugins indexed
- 500+ contributing users
- Comparative analysis available for top 20 plugins

---

## Part 4: Business Model Considerations

### Open Source Core

- Plugin Analyzer: MIT licensed, fully open
- Runtime Monitor: MIT licensed, fully open
- Local analysis requires no account or payment

### Observatory as Service

**Free Tier:**
- Browse public plugin directory
- View aggregate statistics
- Basic comparisons

**Pro Tier ($9/month):**
- Detailed comparative analysis
- Security advisory alerts
- Priority support for plugin authors
- Custom team dashboards

**Enterprise Tier:**
- Private plugin analysis
- Internal marketplace indexing
- Compliance reporting
- SLA guarantees

### Alternative: Foundation Model

Run as a community resource funded by:
- Anthropic sponsorship (ecosystem health)
- Plugin author donations
- Corporate sponsors

---

## Part 5: Open Questions

1. **Data Privacy:** What's the minimum viable telemetry that still produces useful aggregates?

2. **Gaming Resistance:** How do we prevent plugin authors from inflating their metrics?

3. **Anthropic Alignment:** Would Anthropic endorse or integrate this? Compete with it?

4. **Cross-Platform:** Should this cover Codex, OpenCode, and other Claude Code-compatible tools?

5. **Plugin Author Incentives:** How do we encourage authors to optimize for the metrics we surface?

6. **Versioning:** How do we handle plugin updates that change context cost or capabilities?

---

## Appendix A: Compound-Engineering vs Superpowers Analysis

| Dimension | Compound-Engineering | Superpowers |
|-----------|---------------------|-------------|
| **GitHub Stars** | 3,200 | 12,300 |
| **Forks** | 272 | 997 |
| **Commands** | 6 | 3 (+variants) |
| **Agents** | 17 | ~5 |
| **Skills** | 0 | 10+ |
| **Hooks** | 0 | Yes |
| **MCP Servers** | 0 | 0 |
| **Cross-Platform** | Claude Code only | Claude Code, Codex, OpenCode |
| **Primary Pattern** | Parallel agent specialists | Auto-triggering skill workflows |
| **Context Cost (est.)** | ~2,400 baseline | ~1,800 baseline |
| **Philosophy** | "Work compounds on itself" | "Structured TDD workflow" |
| **Best For** | Review-heavy workflows | TDD-first development |

**Recommendation:** These plugins have ~35% feature overlap but different philosophies. Users should choose based on:
- If you want structured planning → review cycles: **Compound-Engineering**
- If you want automatic TDD enforcement and brainstorming: **Superpowers**
- If cross-platform matters: **Superpowers** (supports Codex, OpenCode)

---

## Appendix B: Security Scanning Rules

```yaml
# security_patterns.yaml

high_severity:
  - pattern: "os.system|subprocess.call|subprocess.run"
    context: "hooks/**/*.py"
    message: "Shell execution in hooks - review for injection risks"
  
  - pattern: "eval\\(|exec\\("
    context: "**/*.py"
    message: "Dynamic code execution detected"

  - pattern: "curl.*\\|.*sh"
    context: "**/*.sh"
    message: "Pipe to shell pattern - potential remote code execution"

medium_severity:
  - pattern: "chmod.*777"
    context: "**/*.sh"
    message: "Overly permissive file permissions"
  
  - pattern: "ANTHROPIC_API_KEY|API_KEY|SECRET"
    context: "**/*"
    message: "Potential credential exposure"

info:
  - pattern: "WebFetch\\("
    context: "skills/**/*.md"
    message: "Skill requests web access"
```

---

## Appendix C: Sample CLI Output

```
$ npx plugin-analyzer https://github.com/obra/superpowers

╔══════════════════════════════════════════════════════════════════╗
║                    Plugin Analysis: superpowers                   ║
╠══════════════════════════════════════════════════════════════════╣
║ Repository:     obra/superpowers                                  ║
║ Version:        1.4.0                                             ║
║ License:        MIT                                               ║
║ Stars:          12,300                                            ║
╚══════════════════════════════════════════════════════════════════╝

📦 COMPONENTS
┌──────────────┬───────┬─────────────────────────────────────────┐
│ Type         │ Count │ Notable Items                           │
├──────────────┼───────┼─────────────────────────────────────────┤
│ Commands     │ 3     │ brainstorm, write-plan, execute-plan    │
│ Skills       │ 10    │ test-driven-development, brainstorming  │
│ Agents       │ 5     │ code-reviewer, plan-validator           │
│ Hooks        │ 2     │ session-start, pre-commit               │
│ MCP Servers  │ 0     │ —                                       │
└──────────────┴───────┴─────────────────────────────────────────┘

💾 CONTEXT COST
┌─────────────────────┬────────────────┐
│ Baseline Overhead   │ ~1,800 tokens  │
│ Typical Session     │ ~3,200 tokens  │
│ Maximum (all used)  │ ~6,500 tokens  │
│ Rating              │ ✅ Efficient   │
└─────────────────────┴────────────────┘

🏗️ ARCHITECTURE
  ✅ Skills-first design (context efficient)
  ✅ No always-on MCP servers
  ✅ Auto-triggering workflows reduce manual invocation
  ⚠️ 2 hooks execute shell commands (review recommended)

🔒 SECURITY
  Risk Level: LOW
  
  Findings:
  • [INFO] hooks/session-init.sh executes shell commands
  • [INFO] Requires 'gh' CLI for GitHub integration

🔄 OVERLAP WITH INSTALLED PLUGINS
  • compound-engineering: 35% feature overlap
    - Both provide planning workflows
    - Both provide code review capabilities
    - Recommendation: Choose one based on workflow preference

📊 COMMUNITY SIGNALS
  • High adoption (12.3k stars)
  • Active maintenance (last commit: 2 days ago)
  • Good documentation
  • Cross-platform support (Codex, OpenCode)

────────────────────────────────────────────────────────────────────
VERDICT: Recommended for TDD-focused workflows. Efficient design
with minimal context overhead. Consider disabling compound-engineering
if installed to avoid redundant context costs.
────────────────────────────────────────────────────────────────────
```

---

*Document version 0.1 — For discussion and feedback*
