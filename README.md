# Griffith 🔭

> Plugin Observatory for Claude Code

Griffith helps you evaluate, compare, and monitor Claude Code plugins. Named after the [Griffith Observatory](https://griffithobservatory.org/) in Los Angeles.

## Features

- **Analyze** plugins before installation (context cost, security, architecture)
- **Compare** similar plugins to make informed choices
- **Monitor** plugin usage and identify underutilized components
- **Discover** quality signals missing from the ecosystem

## Installation

```bash
pip install griffith
# or
pipx install griffith
```

## Quick Start

```bash
# Analyze a plugin before installing
griffith analyze https://github.com/EveryInc/compound-engineering

# Compare two plugins
griffith compare compound-engineering superpowers

# Scan your installed plugins
griffith scan-installed
```

## Why Griffith?

The Claude Code plugin ecosystem lacks quality infrastructure that mature ecosystems have:

| Ecosystem | Quality Tools |
|-----------|--------------|
| npm | Download counts, vulnerability scanning, bundle size |
| VS Code | Ratings, reviews, verified publishers |
| **Claude Plugins** | GitHub stars only |

Griffith fills this gap with static analysis, usage tracking, and community intelligence.

## Documentation

- [Design Document](docs/design.md) - Full architecture and roadmap
- [Security Patterns](rules/security_patterns.yaml) - What we scan for

## Development

```bash
git clone https://github.com/GruntworkAI/gruntwork-griffith
cd gruntwork-griffith
poetry install
poetry run pytest
```

## License

MIT

---

*Built by [Gruntwork.ai](https://gruntwork.ai)*
