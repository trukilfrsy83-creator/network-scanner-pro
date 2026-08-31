#!/usr/bin/env python3

import csv
import json
import os
import platform
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from ipaddress import ip_interface
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich import box


# ============================================================
# NETSCOPE
# Defensive Network Security Analysis Suite
#
# Engines:
#   Nmap   -> discovery / port assessment
#   TShark -> traffic monitoring / capture
#
# Designed for networks you own or are authorized to assess.
# ============================================================

console = Console()

BASE_DIR = Path(__file__).resolve().parent
RESULTS = BASE_DIR / "results"
SCANS = RESULTS / "scans"
CAPTURES = RESULTS / "captures"
EVIDENCE = RESULTS / "evidence"
REPORTS = RESULTS / "reports"

for directory in (RESULTS, SCANS, CAPTURES, EVIDENCE, REPORTS):
    directory.mkdir(parents=True, exist_ok=True)

hosts = []
selected_host = None
last_ports = []
capture_process = None
capture_path = None


# ============================================================
# UI
# ============================================================

def clear():
    console.clear()


def title(text, subtitle=""):
    clear()

    body = f"[bold cyan]{text}[/bold cyan]"

    if subtitle:
        body += f"\n[dim]{subtitle}[/dim]"

    console.print(
        Panel.fit(
            body,
            border_style="cyan",
            box=box.DOUBLE,
        )
    )


def pause():
    console.input(
        "\n[dim]Press Enter to continue...[/dim]"
    )


def info(message):
    console.print(
        Panel(
            message,
            border_style="blue",
            box=box.ROUNDED,
        )
    )


def success(message):
    console.print(
        Panel(
            f"[bold green]✓[/bold green] {message}",
            border_style="green",
            box=box.ROUNDED,
        )
    )


def error(message):
    console.print(
        Panel(
            f"[bold red]✗[/bold red] {message}",
            border_style="red",
            box=box.ROUNDED,
        )
    )


# ============================================================
# COMMANDS
# ============================================================

def command_exists(name):
    return shutil.which(name) is not None


def run(command, timeout=60):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None


# ============================================================
# NETWORK DETECTION
# ============================================================

def get_local_network():
    system = platform.system()

    if system == "Linux":
        result = run(
            [
                "ip",
                "-4",
                "-o",
                "addr",
                "show",
                "scope",
                "global",
            ]
        )

        if not result:
            return None, None, None

        for line in result.stdout.splitlines():
            parts = line.split()

            try:
                interface = parts[1]
                address = parts[3]

                iface = ip_interface(address)

                return (
                    interface,
                    str(iface.ip),
                    str(iface.network),
                )

            except (IndexError, ValueError):
                continue

    elif system == "Darwin":
        result = run(["ifconfig"])

        if not result:
            return None, None, None

        current = None

        for line in result.stdout.splitlines():

            if not line.startswith("\t"):
                current = line.split(":")[0]

            if (
                "inet " in line
                and "127.0.0.1" not in line
            ):
                parts = line.split()

                try:
                    ip = parts[1]

                    # macOS ifconfig normally exposes netmask.
                    mask_index = parts.index("netmask") + 1
                    mask = parts[mask_index]

                    import ipaddress

                    network = ipaddress.IPv4Network(
                        f"{ip}/{mask}",
                        strict=False,
                    )

                    return (
                        current,
                        ip,
                        str(network),
                    )

                except Exception:
                    continue

    elif system == "Windows":
        result = run(["ipconfig"])

        if not result:
            return None, None, None

        ip = None
        mask = None

        for line in result.stdout.splitlines():

            if "IPv4 Address" in line:
                ip = line.split(":")[-1].strip()

            elif "Subnet Mask" in line:
                mask = line.split(":")[-1].strip()

            if ip and mask:
                try:
                    import ipaddress

                    network = ipaddress.IPv4Network(
                        f"{ip}/{mask}",
                        strict=False,
                    )

                    return (
                        "unknown",
                        ip,
                        str(network),
                    )

                except Exception:
                    pass

    return None, None, None


# ============================================================
# DEVICE NAME RESOLUTION
# ============================================================

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ============================================================
# DISCOVERY
# ============================================================

def discover():
    global hosts

    title(
        "NETWORK DISCOVERY",
        "Real host discovery using Nmap",
    )

    if not command_exists("nmap"):
        error("Nmap is not installed.")
        pause()
        return

    interface, local_ip, network = get_local_network()

    if not network:
        error("Could not determine the active IPv4 network.")
        pause()
        return

    console.print(
        Panel(
            f"[bold]Interface:[/bold] {interface}\n"
            f"[bold]Local IP:[/bold] {local_ip}\n"
            f"[bold]Network:[/bold] {network}\n\n"
            f"[cyan]Engine:[/cyan] Nmap host discovery",
            title="NETWORK",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    console.print(
        "\n[cyan]Scanning network...[/cyan]\n"
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    xml_file = SCANS / f"discovery_{timestamp}.xml"

    result = run(
        [
            "nmap",
            "-sn",
            "-oX",
            str(xml_file),
            network,
        ],
        timeout=180,
    )

    if not result:
        error("Nmap scan timed out.")
        pause()
        return

    if result.returncode != 0:
        error(
            result.stderr.strip()
            or "Nmap returned an error."
        )
        pause()
        return

    try:
        root = ET.parse(xml_file).getroot()
    except Exception as exc:
        error(f"Could not parse Nmap XML: {exc}")
        pause()
        return

    discovered = []

    for host in root.findall("host"):

        status = host.find("status")

        if status is None:
            continue

        if status.get("state") != "up":
            continue

        ip = None
        mac = None
        vendor = None

        for address in host.findall("address"):

            addr_type = address.get("addrtype")

            if addr_type == "ipv4":
                ip = address.get("addr")

            elif addr_type == "mac":
                mac = address.get("addr")
                vendor = address.get("vendor")

        if not ip:
            continue

        hostname = None

        hostnames = host.find("hostnames")

        if hostnames is not None:
            node = hostnames.find("hostname")

            if node is not None:
                hostname = node.get("name")

        if not hostname:
            hostname = resolve_hostname(ip)

        if not hostname:
            hostname = "Unknown"

        if not vendor:
            vendor = "Unknown"

        device_name = (
            hostname
            if hostname != "Unknown"
            else vendor
        )

        discovered.append(
            {
                "ip": ip,
                "mac": mac or "Not detected",
                "hostname": hostname,
                "vendor": vendor,
                "device": device_name,
                "status": "ONLINE",
            }
        )

    discovered.sort(
        key=lambda x: tuple(
            int(part)
            for part in x["ip"].split(".")
        )
    )

    hosts = discovered

    show_hosts()

    json_file = SCANS / f"discovery_{timestamp}.json"

    with json_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            {
                "scan_time": datetime.now().isoformat(
                    timespec="seconds"
                ),
                "interface": interface,
                "local_ip": local_ip,
                "network": network,
                "hosts": hosts,
            },
            file,
            indent=4,
        )

    console.print(
        f"\n[green]Evidence scan saved:[/green] "
        f"{json_file}"
    )

    pause()


def show_hosts():
    title(
        "DISCOVERED DEVICES",
        f"{len(hosts)} active host(s)",
    )

    if not hosts:
        info("No discovered devices.")
        return

    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )

    table.add_column(
        "#",
        justify="center",
        width=4,
    )

    table.add_column(
        "DEVICE",
        style="bold cyan",
    )

    table.add_column(
        "IP ADDRESS",
        style="green",
    )

    table.add_column(
        "MAC ADDRESS",
    )

    table.add_column(
        "VENDOR",
    )

    table.add_column(
        "STATUS",
        justify="center",
    )

    for number, host in enumerate(hosts, 1):

        table.add_row(
            str(number),
            host["device"],
            host["ip"],
            host["mac"],
            host["vendor"],
            "[green]● ONLINE[/green]",
        )

    console.print(table)

    console.print(
        Panel(
            "[bold]Select a device by number from "
            "the Device menu to continue analysis.[/bold]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


# ============================================================
# DEVICE SELECTION
# ============================================================

def select_host():
    global selected_host

    title(
        "DEVICE SELECTION",
        "Choose a discovered host",
    )

    if not hosts:
        error(
            "No hosts available. Run Network Discovery first."
        )
        pause()
        return

    for index, host in enumerate(hosts, 1):

        console.print(
            Panel(
                f"[bold cyan]{host['device']}[/bold cyan]\n"
                f"IP: [green]{host['ip']}[/green]\n"
                f"MAC: {host['mac']}\n"
                f"Vendor: {host['vendor']}",
                title=f"DEVICE {index}",
                border_style="blue",
                box=box.ROUNDED,
            )
        )

    value = Prompt.ask(
        "\nDevice number or IP"
    ).strip()

    chosen = None

    if value.isdigit():

        index = int(value)

        if 1 <= index <= len(hosts):
            chosen = hosts[index - 1]

    else:

        for host in hosts:
            if host["ip"] == value:
                chosen = host
                break

    if not chosen:
        error("Device not found.")
        pause()
        return

    selected_host = chosen

    success(
        f"Selected: {chosen['device']} "
        f"({chosen['ip']})"
    )

    pause()


# ============================================================
# PORT ASSESSMENT
# ============================================================

def assess_ports():
    global last_ports

    title(
        "PORT ASSESSMENT",
        "Real service discovery using Nmap",
    )

    if not command_exists("nmap"):
        error("Nmap is not installed.")
        pause()
        return

    if not selected_host:
        error(
            "Select a device first."
        )
        pause()
        return

    ip = selected_host["ip"]

    console.print(
        Panel(
            f"[bold]Target:[/bold] "
            f"[green]{ip}[/green]\n"
            f"[bold]Device:[/bold] "
            f"{selected_host['device']}\n\n"
            f"[cyan]Nmap service assessment[/cyan]",
            title="TARGET",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    console.print(
        "\n[yellow]Running service assessment...[/yellow]\n"
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    xml_file = SCANS / (
        f"assessment_{ip}_{timestamp}.xml"
    )

    result = run(
        [
            "nmap",
            "-sV",
            "--version-light",
            "-T3",
            "-oX",
            str(xml_file),
            ip,
        ],
        timeout=180,
    )

    if not result:
        error("Assessment timed out.")
        pause()
        return

    if result.returncode != 0:
        error(
            result.stderr.strip()
            or "Nmap assessment failed."
        )
        pause()
        return

    try:
        root = ET.parse(xml_file).getroot()
    except Exception as exc:
        error(f"XML parsing failed: {exc}")
        pause()
        return

    last_ports = []

    for port in root.findall(
        ".//ports/port"
    ):

        state_node = port.find("state")

        if state_node is None:
            continue

        state = state_node.get(
            "state",
            "unknown",
        )

        if state != "open":
            continue

        service = port.find("service")

        service_name = "unknown"
        product = ""
        version = ""

        if service is not None:

            service_name = service.get(
                "name",
                "unknown",
            )

            product = service.get(
                "product",
                "",
            )

            version = service.get(
                "version",
                "",
            )

        last_ports.append(
            {
                "port": int(
                    port.get("portid", "0")
                ),
                "protocol": port.get(
                    "protocol",
                    "tcp",
                ),
                "state": state,
                "service": service_name,
                "product": product,
                "version": version,
            }
        )

    display_ports()

    pause()


def display_ports():
    title(
        "OPEN SERVICES",
        selected_host["ip"]
        if selected_host
        else "",
    )

    if not last_ports:
        info(
            "No open TCP services were identified "
            "by this assessment."
        )
        return

    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )

    table.add_column("PORT")
    table.add_column("PROTO")
    table.add_column("STATE")
    table.add_column("SERVICE")
    table.add_column("PRODUCT")
    table.add_column("VERSION")

    for item in last_ports:

        table.add_row(
            str(item["port"]),
            item["protocol"],
            "[green]OPEN[/green]",
            item["service"],
            item["product"] or "-",
            item["version"] or "-",
        )

    console.print(table)


# ============================================================
# RISK ANALYSIS
# ============================================================

def risk_analysis():
    title(
        "RISK ANALYSIS",
        "Defensive interpretation of discovered services",
    )

    if not selected_host:
        error("Select a device first.")
        pause()
        return

    if not last_ports:
        error(
            "Run Port Assessment first."
        )
        pause()
        return

    findings = []

    for item in last_ports:

        port = item["port"]
        service = item["service"].lower()

        risk = "LOW"
        reason = "Open service identified."

        if port in (21, 23):
            risk = "HIGH"
            reason = (
                "Legacy plaintext administration protocol "
                "may expose credentials or management access."
            )

        elif port in (445, 139):
            risk = "HIGH"
            reason = (
                "Windows file-sharing services should be "
                "restricted to trusted network segments."
            )

        elif port in (3389, 5900):
            risk = "MEDIUM"
            reason = (
                "Remote administration service detected. "
                "Restrict access and enforce strong authentication."
            )

        elif port in (80, 8080):
            risk = "MEDIUM"
            reason = (
                "HTTP service detected. Verify whether "
                "unencrypted management traffic is intended."
            )

        elif service in (
            "telnet",
            "ftp",
        ):
            risk = "HIGH"
            reason = (
                "Legacy service detected. Prefer encrypted "
                "alternatives where possible."
            )

        findings.append(
            {
                **item,
                "risk": risk,
                "reason": reason,
            }
        )

    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )

    table.add_column("PORT")
    table.add_column("SERVICE")
    table.add_column("RISK")
    table.add_column("ASSESSMENT")

    for finding in findings:

        risk = finding["risk"]

        if risk == "HIGH":
            risk_display = "[bold red]HIGH[/bold red]"
        elif risk == "MEDIUM":
            risk_display = "[yellow]MEDIUM[/yellow]"
        else:
            risk_display = "[green]LOW[/green]"

        table.add_row(
            str(finding["port"]),
            finding["service"],
            risk_display,
            finding["reason"],
        )

    console.print(table)

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    path = REPORTS / (
        f"risk_{selected_host['ip']}_{timestamp}.json"
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            {
                "target": selected_host,
                "findings": findings,
            },
            file,
            indent=4,
        )

    console.print(
        f"\n[green]Risk report saved:[/green] {path}"
    )

    pause()


# ============================================================
# TSHARK
# ============================================================

def tshark_interfaces():
    result = run(
        [
            "tshark",
            "-D",
        ]
    )

    if not result or result.returncode != 0:
        return []

    interfaces = []

    for line in result.stdout.splitlines():

        if ". " not in line:
            continue

        number, name = line.split(
            ". ",
            1,
        )

        interfaces.append(
            {
                "number": number.strip(),
                "name": name.strip(),
            }
        )

    return interfaces


def traffic_monitor():
    global capture_process
    global capture_path

    title(
        "TRAFFIC MONITOR",
        "Real packet capture using TShark",
    )

    if not command_exists("tshark"):
        error("TShark is not installed.")
        pause()
        return

    interfaces = tshark_interfaces()

    if not interfaces:
        error(
            "Could not retrieve capture interfaces."
        )
        pause()
        return

    table = Table(
        title="CAPTURE INTERFACES",
        box=box.ROUNDED,
    )

    table.add_column("#")
    table.add_column("INTERFACE")

    for item in interfaces:

        table.add_row(
            item["number"],
            item["name"],
        )

    console.print(table)

    selected = Prompt.ask(
        "\nInterface number",
        default=interfaces[0]["number"],
    )

    interface = None

    for item in interfaces:

        if item["number"] == selected:
            interface = item["name"]
            break

    if not interface:
        error("Interface not found.")
        pause()
        return

    if capture_process:
        error(
            "A capture is already running."
        )
        pause()
        return

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    capture_path = CAPTURES / (
        f"capture_{timestamp}.pcapng"
    )

    console.print(
        Panel(
            f"[bold]Interface:[/bold] {interface}\n"
            f"[bold]Output:[/bold] {capture_path}\n\n"
            "[yellow]Capture is starting.[/yellow]\n"
            "Press Ctrl+C to stop.",
            title="LIVE CAPTURE",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    try:

        capture_process = subprocess.Popen(
            [
                "tshark",
                "-i",
                interface,
                "-w",
                str(capture_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        while True:
            if capture_process.poll() is not None:
                break

            time.sleep(0.5)

    except KeyboardInterrupt:

        if capture_process:
            capture_process.terminate()

            try:
                capture_process.wait(
                    timeout=5
                )
            except subprocess.TimeoutExpired:
                capture_process.kill()

        capture_process = None

        if capture_path.exists():
            success(
                f"Capture saved: {capture_path}"
            )
        else:
            error(
                "No capture file was created."
            )

        pause()


# ============================================================
# TRAFFIC ANALYSIS
# ============================================================

def analyze_capture():
    title(
        "CAPTURE ANALYSIS",
        "Analyze an existing PCAP/PCAPNG using TShark",
    )

    if not command_exists("tshark"):
        error("TShark is not installed.")
        pause()
        return

    files = sorted(
        CAPTURES.glob("*.pcap*"),
        reverse=True,
    )

    if not files:
        info(
            "No capture files found."
        )
        pause()
        return

    table = Table(
        title="AVAILABLE CAPTURES",
        box=box.ROUNDED,
    )

    table.add_column("#")
    table.add_column("FILE")
    table.add_column("SIZE")

    for index, path in enumerate(files, 1):

        size = path.stat().st_size

        table.add_row(
            str(index),
            path.name,
            f"{size:,} bytes",
        )

    console.print(table)

    value = Prompt.ask(
        "Capture number"
    )

    if not value.isdigit():
        error("Invalid selection.")
        pause()
        return

    index = int(value)

    if not 1 <= index <= len(files):
        error("Capture not found.")
        pause()
        return

    path = files[index - 1]

    result = run(
        [
            "tshark",
            "-r",
            str(path),
            "-q",
            "-z",
            "io,phs",
        ],
        timeout=120,
    )

    if not result:
        error("Capture analysis timed out.")
        pause()
        return

    if result.returncode != 0:
        error(
            result.stderr.strip()
            or "TShark analysis failed."
        )
        pause()
        return

    console.print(
        Panel(
            result.stdout.strip()
            or "No protocol statistics returned.",
            title=f"PROTOCOL STATISTICS — {path.name}",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    pause()


# ============================================================
# EVIDENCE
# ============================================================

def save_evidence():
    title(
        "EVIDENCE",
        "Save current assessment context",
    )

    if not selected_host:
        error(
            "Select a device first."
        )
        pause()
        return

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    path = EVIDENCE / (
        f"evidence_{timestamp}.json"
    )

    evidence = {
        "created_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "platform": platform.platform(),
        "target": selected_host,
        "ports": last_ports,
        "capture": (
            str(capture_path)
            if capture_path
            else None
        ),
    }

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            evidence,
            file,
            indent=4,
        )

    success(
        f"Evidence saved: {path}"
    )

    pause()


# ============================================================
# EXPORT
# ============================================================

def export_data():
    title(
        "EXPORT",
        "Export discovered hosts",
    )

    if not hosts:
        error(
            "No discovery results available."
        )
        pause()
        return

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    json_path = REPORTS / (
        f"network_{timestamp}.json"
    )

    csv_path = REPORTS / (
        f"network_{timestamp}.csv"
    )

    with json_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            hosts,
            file,
            indent=4,
        )

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "ip",
                "mac",
                "hostname",
                "vendor",
                "device",
                "status",
            ],
        )

        writer.writeheader()
        writer.writerows(hosts)

    success(
        f"JSON: {json_path}\n"
        f"CSV: {csv_path}"
    )

    pause()


# ============================================================
# SYSTEM STATUS
# ============================================================

def system_status():
    title(
        "SYSTEM STATUS",
        "NETSCOPE engine availability",
    )

    interface, local_ip, network = (
        get_local_network()
    )

    table = Table(
        box=box.ROUNDED,
        show_lines=True,
    )

    table.add_column("COMPONENT")
    table.add_column("STATUS")
    table.add_column("DETAIL")

    tools = [
        (
            "Nmap",
            command_exists("nmap"),
            shutil.which("nmap") or "-",
        ),
        (
            "TShark",
            command_exists("tshark"),
            shutil.which("tshark") or "-",
        ),
    ]

    for name, available, detail in tools:

        status = (
            "[green]READY[/green]"
            if available
            else "[red]MISSING[/red]"
        )

        table.add_row(
            name,
            status,
            detail,
        )

    table.add_row(
        "Interface",
        (
            "[green]READY[/green]"
            if interface
            else "[red]UNKNOWN[/red]"
        ),
        interface or "-",
    )

    table.add_row(
        "IPv4",
        (
            "[green]READY[/green]"
            if local_ip
            else "[red]UNKNOWN[/red]"
        ),
        local_ip or "-",
    )

    table.add_row(
        "Network",
        (
            "[green]READY[/green]"
            if network
            else "[red]UNKNOWN[/red]"
        ),
        network or "-",
    )

    console.print(table)

    pause()


# ============================================================
# MAIN MENU
# ============================================================

def menu():
    while True:

        title(
            "NETSCOPE",
            "Network Security Analysis Suite",
        )

        interface, local_ip, network = (
            get_local_network()
        )

        console.print(
            Panel(
                f"[bold]Interface:[/bold] "
                f"{interface or 'Unknown'}\n"
                f"[bold]Local IP:[/bold] "
                f"{local_ip or 'Unknown'}\n"
                f"[bold]Network:[/bold] "
                f"{network or 'Unknown'}\n"
                f"[bold]Selected:[/bold] "
                f"{selected_host['ip'] if selected_host else 'None'}",
                title="NETWORK STATUS",
                border_style="blue",
                box=box.ROUNDED,
            )
        )

        menu_table = Table(
            title="MAIN MENU",
            box=box.DOUBLE,
            expand=True,
        )

        menu_table.add_column(
            "#",
            justify="center",
            width=5,
        )

        menu_table.add_column(
            "MODULE",
            style="bold cyan",
        )

        menu_table.add_column(
            "FUNCTION",
        )

        entries = [
            ("1", "🔎 Network Discovery",
             "Discover online devices"),
            ("2", "🖥️ Device Selection",
             "Select a target for assessment"),
            ("3", "🔍 Port Assessment",
             "Identify open services"),
            ("4", "🛡️ Risk Analysis",
             "Assess exposed services"),
            ("5", "📡 Traffic Monitor",
             "Live packet capture"),
            ("6", "📊 Capture Analysis",
             "Analyze PCAP/PCAPNG"),
            ("7", "📸 Evidence",
             "Save assessment evidence"),
            ("8", "💾 Export",
             "Export network results"),
            ("9", "⚙️ System Status",
             "Check security engines"),
            ("0", "❌ Exit",
             "Close NETSCOPE"),
        ]

        for number, module, function in entries:

            menu_table.add_row(
                number,
                module,
                function,
            )

        console.print(menu_table)

        choice = Prompt.ask(
            "\nSelect an option",
            choices=[
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "8",
                "9",
                "0",
            ],
        )

        if choice == "1":
            discover()

        elif choice == "2":
            select_host()

        elif choice == "3":
            assess_ports()

        elif choice == "4":
            risk_analysis()

        elif choice == "5":
            traffic_monitor()

        elif choice == "6":
            analyze_capture()

        elif choice == "7":
            save_evidence()

        elif choice == "8":
            export_data()

        elif choice == "9":
            system_status()

        elif choice == "0":
            clear()
            console.print(
                Panel.fit(
                    "[bold cyan]NETSCOPE[/bold cyan]\n"
                    "[green]Session closed safely.[/green]",
                    border_style="cyan",
                    box=box.DOUBLE,
                )
            )
            break


if __name__ == "__main__":
    menu()
