# Griffith - Claude Code Plugin Observatory

## Overview

Griffith is a plugin evaluation and analytics system for the Claude Code ecosystem. Named after the Griffith Observatory in Los Angeles, it provides visibility into plugin quality, usage, and security.

## Architecture

Three-layer system (see `docs/design.md` for full details):

1. **Plugin Analyzer** - Static analysis before installation
2. **Runtime Monitor** - Usage tracking during sessions
3. **Plugin Observatory** - Public aggregation service (future)

## Current Phase

**Phase 1: Plugin Analyzer CLI**

Building a Python CLI tool that analyzes plugins before installation:
- Component inventory (commands, agents, skills, hooks, MCP servers)
- Context cost estimation
- Security scanning
- Architecture assessment
- Overlap detection with installed plugins

## Tech Stack

- **Language**: Python 3.11+
- **CLI Framework**: Click or Typer
- **Token Estimation**: tiktoken
- **Output**: Rich for terminal formatting
- **Data**: JSON/YAML for rules and reports

## Project Structure

```
gruntwork-griffith/
├── src/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── analyzer/
│   │   ├── inventory.py    # Parse plugin structure
│   │   ├── tokenizer.py    # Estimate token costs
│   │   ├── security.py     # Security scanning
│   │   ├── architecture.py # Design pattern assessment
│   │   └── overlap.py      # Redundancy detection
│   └── reporter.py         # Generate reports
├── rules/
│   ├── security_patterns.yaml
│   ├── efficiency_heuristics.yaml
│   └── known_overlaps.yaml
├── docs/
│   └── design.md           # Full design document
├── tests/
├── pyproject.toml
└── README.md
```

## Commands

```bash
# Analyze a plugin
griffith analyze https://github.com/org/plugin

# Compare two plugins
griffith compare plugin1 plugin2

# Scan installed plugins
griffith scan-installed
```

## Development

```bash
poetry install
poetry run pytest
poetry run griffith --help
```

## Related Projects

- **lastmilefirst** - Overwatch provides basic runtime tracking (invocation counts)
- **compound-engineering** - Security-sentinel agent for manual audits

*Inherits from ~/Code/gruntwork/CLAUDE.md*
