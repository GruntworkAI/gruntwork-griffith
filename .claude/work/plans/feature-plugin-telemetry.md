# Feature: Plugin Telemetry Platform

**Status:** planning
**Priority:** medium
**Created:** 2026-01-30

## Summary

Griffith should provide a centralized telemetry platform that Claude Code plugins can optionally use to collect anonymous usage statistics (with user consent).

## Background: How We Got Here

### Origin: lastmilefirst Plugin Inventory

While building `/run-plugin-inventory` for the lastmilefirst plugin, we added usage tracking via a simple invocations log:

```
~/.claude/lastmilefirst/invocations.log
1769649279|skill
1769726428|skill
```

This log is populated by lastmilefirst's PostToolUse hooks and displayed in the inventory output:

```
lastmilefirst@gruntwork-marketplace  v0.9.5
  Usage (last 7 days):
    skill: 17  agent: 5
    Total: 22
```

### Problem: Cross-Plugin Tracking

We noticed that **compound-engineering** (another installed plugin) showed no usage data because:
1. It has no hooks directory
2. Each plugin would need to implement its own tracking
3. No standard exists for cross-plugin usage tracking

### Discussion: Options Considered

| Option | Description | Confidence |
|--------|-------------|------------|
| Centralized log file | All plugins write to shared location | Medium-Low (requires coordination) |
| Plugin-specific logs + aggregator | Each plugin logs separately, we aggregate | Medium |
| Claude Code native | Request Anthropic add built-in tracking | High if implemented, but out of our control |
| Hook convention | Propose standard pattern plugins can adopt | Low-Medium (voluntary adoption) |

### Decision: Griffith as Telemetry Platform

Rather than building telemetry into lastmilefirst (a plugin focused on expert consultation and project organization), it makes more sense for **Griffith** (the Plugin Observatory) to provide this capability:

1. **Separation of concerns** - Griffith is already about plugin analysis
2. **Reusable** - Multiple plugins can use the same backend
3. **Consistent** - One place for consent handling, privacy policy
4. **Natural fit** - "Observatory" implies observation/metrics

## Proposed Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Griffith Backend                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ API Gateway │  │ Lambda/     │  │ DynamoDB/           │ │
│  │             │──│ Function    │──│ Analytics Store     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
        ▲                    ▲                    ▲
        │                    │                    │
   ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
   │ lastmile │          │compound-│          │ other   │
   │ first    │          │ eng     │          │ plugins │
   └──────────┘          └─────────┘          └─────────┘
```

### Data Collected (with consent)

```json
{
  "plugin": "lastmilefirst",
  "plugin_version": "0.9.6",
  "period": "2026-01-23/2026-01-30",
  "invocations": {
    "review-project": 5,
    "organize-project": 3,
    "consult-expert": 12
  },
  "platform": "darwin"
}
```

**NOT collected:**
- File paths
- Content or arguments
- Individual timestamps
- User identity
- Project names

### Consent Flow

```
First run of any participating plugin:
┌─────────────────────────────────────────────────────────┐
│ Help improve Claude Code plugins?                       │
│                                                         │
│ Share anonymous usage stats (command counts only)?      │
│ Data is aggregated weekly and contains no personal info.│
│                                                         │
│ [Y] Yes  [N] No  [?] What's collected                   │
└─────────────────────────────────────────────────────────┘
```

Preference stored in: `~/.claude/griffith/config.json`
```json
{
  "telemetry_consent": true,
  "consent_date": "2026-01-30",
  "consent_version": "1.0"
}
```

### SDK for Plugin Authors

Griffith provides a simple Python module plugins can use:

```python
# In any plugin's hooks
from griffith_telemetry import log_invocation, is_consent_given

if is_consent_given():
    log_invocation(
        plugin="lastmilefirst",
        skill="review-project",
        version="0.9.6"
    )
```

Or a shell script for simpler hooks:
```bash
~/.claude/griffith/bin/log-invocation lastmilefirst review-project
```

## Backend Options

| Option | Complexity | Cost | Notes |
|--------|------------|------|-------|
| **Lambda + DynamoDB** | Medium | ~$0/month | AWS native, fits gruntwork patterns |
| **PostHog** | Low | Free tier | Managed, but external dependency |
| **Plausible** | Low | Free tier | Privacy-focused, good reputation |
| **Cloudflare Workers + D1** | Medium | Free tier | Edge-native, fast |

**Recommendation:** Start with Lambda + DynamoDB to keep it within gruntwork infrastructure patterns. Could migrate later if needed.

## Implementation Phases

### Phase 1: Local Tracking Improvements
- Improve lastmilefirst logging to capture specific skill names (not just "skill")
- Document the log format as a potential standard
- No backend yet, just better local data

### Phase 2: Griffith SDK
- Create `griffith-telemetry` Python package
- Implement consent management
- Local-only mode (logs to ~/.claude/griffith/usage.log)
- Can be used by plugins without backend

### Phase 3: Backend & Submission
- Deploy simple API endpoint
- Implement weekly batch submission
- Add dashboard for viewing aggregated stats
- Privacy policy and documentation

### Phase 4: Cross-Plugin Adoption
- Document the SDK for other plugin authors
- Propose as a convention to compound-engineering and others
- Consider contributing to Claude Code as a standard

## Open Questions

1. **Granularity:** Weekly batches vs. real-time?
2. **Anonymization:** Hash any identifiers or just don't collect them?
3. **Opt-in vs. Opt-out:** Opt-in is more respectful, opt-out gets more data
4. **Public stats:** Should aggregate plugin usage be publicly viewable?

## Success Metrics

- [ ] lastmilefirst reports granular skill usage locally
- [ ] Griffith SDK exists and is documented
- [ ] At least one plugin successfully submitting telemetry
- [ ] Dashboard showing aggregate usage patterns

## Related

- lastmilefirst `/run-plugin-inventory` command
- lastmilefirst invocations.log format
- Griffith static plugin analysis features
