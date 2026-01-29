"""Griffith CLI - Plugin analysis and comparison tools"""

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option()
def main():
    """Griffith - Plugin Observatory for Claude Code

    Analyze, compare, and monitor Claude Code plugins.
    """
    pass


@main.command()
@click.argument("source")
def analyze(source: str):
    """Analyze a plugin from a GitHub repo or local path.

    SOURCE can be:
    - GitHub repo: owner/repo or https://github.com/owner/repo
    - Local path: ./my-plugin or /path/to/plugin
    """
    console.print(f"[bold]Analyzing plugin:[/bold] {source}")
    console.print("[dim]Not yet implemented - see docs/design.md for roadmap[/dim]")


@main.command()
@click.argument("plugin1")
@click.argument("plugin2")
def compare(plugin1: str, plugin2: str):
    """Compare two plugins side-by-side.

    Shows context cost, architecture, features, and overlap.
    """
    console.print(f"[bold]Comparing:[/bold] {plugin1} vs {plugin2}")
    console.print("[dim]Not yet implemented - see docs/design.md for roadmap[/dim]")


@main.command("scan-installed")
def scan_installed():
    """Scan all installed plugins for analysis.

    Reports on context cost, usage, and recommendations.
    """
    console.print("[bold]Scanning installed plugins...[/bold]")
    console.print("[dim]Not yet implemented - see docs/design.md for roadmap[/dim]")


if __name__ == "__main__":
    main()
