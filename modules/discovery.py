import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def discover_hosts(network):
    if not shutil.which("nmap"):
        console.print(
            Panel(
                "[bold red]Nmap غير مثبت.[/bold red]",
                title="Discovery Error",
                border_style="red",
            )
        )
        return []

    console.print(
        Panel(
            f"[bold cyan]فحص حقيقي للشبكة[/bold cyan]\n\n"
            f"Network: {network}\n"
            f"Engine: Nmap\n"
            f"Mode: Host Discovery",
            title="🌐 NETWORK SCAN",
            border_style="cyan",
        )
    )

    xml_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".xml",
            delete=False
        ) as temp:
            xml_path = Path(temp.name)

        result = subprocess.run(
            [
                "nmap",
                "-sn",
                "-oX",
                str(xml_path),
                str(network),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        if result.returncode != 0:
            console.print(
                Panel(
                    result.stderr.strip()
                    or "Nmap returned an error.",
                    title="Nmap Error",
                    border_style="red",
                )
            )
            return []

        root = ET.parse(xml_path).getroot()
        hosts = []

        for host in root.findall("host"):

            status = host.find("status")

            if status is None or status.get("state") != "up":
                continue

            ip = None
            mac = "Not detected"
            vendor = "Not detected"
            hostname = "Not resolved"

            for address in host.findall("address"):

                addr_type = address.get("addrtype")

                if addr_type == "ipv4":
                    ip = address.get("addr")

                elif addr_type == "mac":
                    mac = address.get(
                        "addr",
                        "Not detected"
                    )
                    vendor = address.get(
                        "vendor",
                        "Not detected"
                    )

            hostnames = host.find("hostnames")

            if hostnames is not None:
                hostname_node = hostnames.find("hostname")

                if hostname_node is not None:
                    hostname = hostname_node.get(
                        "name",
                        "Not resolved"
                    )

            if not ip:
                continue

            if hostname != "Not resolved":
                name = hostname
            elif vendor != "Not detected":
                name = vendor
            else:
                name = "Unknown Device"

            hosts.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "device_type": name,
                    "display_name": name,
                    "status": "ONLINE",
                }
            )

        hosts.sort(
            key=lambda x: tuple(
                int(part)
                for part in x["ip"].split(".")
            )
        )

        display_results(hosts)

        return hosts

    except subprocess.TimeoutExpired:
        console.print(
            Panel(
                "[bold red]انتهى وقت الفحص.[/bold red]",
                title="Scan Timeout",
                border_style="red",
            )
        )
        return []

    except ET.ParseError:
        console.print(
            Panel(
                "[bold red]تعذر قراءة نتيجة Nmap.[/bold red]",
                title="XML Error",
                border_style="red",
            )
        )
        return []

    finally:
        if xml_path and xml_path.exists():
            try:
                xml_path.unlink()
            except OSError:
                pass


def display_results(hosts):

    if not hosts:
        console.print(
            Panel(
                "[yellow]لم يتم العثور على أجهزة متاحة.[/yellow]",
                title="RESULT",
                border_style="yellow",
            )
        )
        return

    table = Table(
        title="🌐 DISCOVERED DEVICES",
        show_lines=True,
        expand=True,
    )

    table.add_column("#", justify="center", width=4)
    table.add_column("DEVICE", style="bold cyan")
    table.add_column("IP ADDRESS", style="green")
    table.add_column("MAC ADDRESS")
    table.add_column("VENDOR")
    table.add_column("STATUS", justify="center")

    for number, host in enumerate(hosts, 1):

        table.add_row(
            str(number),
            host["display_name"],
            host["ip"],
            host["mac"],
            host["vendor"],
            "● ONLINE",
        )

    console.print(table)

    console.print(
        Panel(
            f"[bold green]{len(hosts)}[/bold green] "
            "active device(s) discovered.",
            title="SCAN COMPLETE",
            border_style="green",
        )
    )
