from datetime import datetime

from rich.console import Console
from rich.table import Table


console = Console()


class ResponseManager:

    def __init__(self):

        self.blocked = []

    def block(self, ip, mac):

        for item in self.blocked:

            if item["ip"] == ip:

                console.print(
                    "[yellow]Device is already blocked "
                    "in this session.[/yellow]"
                )

                return

        record = {
            "ip": ip,
            "mac": mac,
            "blocked_at": datetime.now().isoformat(
                timespec="seconds"
            ),
            "status": "BLOCKED",
        }

        self.blocked.append(record)

        console.print(
            "\n[bold green]✓ Device marked for containment.[/bold green]"
        )

        console.print(
            "[dim]Current version records the containment "
            "decision locally.[/dim]"
        )

        console.print(
            "[yellow]A router/firewall adapter is required "
            "for real network-level enforcement.[/yellow]"
        )

    def unblock(self, ip):

        original_length = len(self.blocked)

        self.blocked = [
            item
            for item in self.blocked
            if item["ip"] != ip
        ]

        if len(self.blocked) < original_length:

            console.print(
                "[bold green]✓ Device removed "
                "from containment list.[/bold green]"
            )

        else:

            console.print(
                "[yellow]Device was not in the containment list.[/yellow]"
            )

    def show_blocked(self):

        if not self.blocked:

            console.print(
                "[yellow]No blocked devices.[/yellow]"
            )

            return

        table = Table(
            title="🚧 Contained Devices",
            show_lines=True,
        )

        table.add_column("IP")
        table.add_column("MAC")
        table.add_column("Time")
        table.add_column("Status")

        for item in self.blocked:

            table.add_row(
                item["ip"],
                item["mac"],
                item["blocked_at"],
                item["status"],
            )

        console.print(table)
