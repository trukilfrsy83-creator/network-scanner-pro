import shutil
import subprocess

from rich.console import Console
from rich.table import Table


console = Console()


def assess_target(ip):

    if not shutil.which("nmap"):

        console.print(
            "[red]Nmap is not installed.[/red]"
        )

        return []

    console.print(
        f"\n[cyan]Assessing target:[/cyan] "
        f"[bold]{ip}[/bold]"
    )

    try:

        process = subprocess.run(
            [
                "nmap",
                "-sV",
                "--version-light",
                ip,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

    except subprocess.TimeoutExpired:

        console.print(
            "[red]Assessment timed out.[/red]"
        )

        return []

    if process.returncode != 0:

        console.print(
            "[red]Nmap assessment failed.[/red]"
        )

        return []

    results = []

    for line in process.stdout.splitlines():

        line = line.strip()

        if (
            "/tcp" in line
            and ("open" in line or "filtered" in line)
        ):

            parts = line.split()

            if len(parts) >= 3:

                port = parts[0]
                state = parts[1]
                service = parts[2]

                version = " ".join(parts[3:])

                results.append(
                    {
                        "port": port,
                        "state": state,
                        "service": service,
                        "version": version,
                    }
                )

    table = Table(
        title=f"Target Assessment — {ip}",
        show_lines=True,
    )

    table.add_column("Port")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Version")

    for item in results:

        table.add_row(
            item["port"],
            item["state"],
            item["service"],
            item["version"],
        )

    console.print(table)

    console.print(
        f"\n[bold green]✓ "
        f"{len(results)} service result(s) found.[/bold green]"
    )

    return results
