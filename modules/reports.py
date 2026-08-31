import csv
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console


console = Console()

RESULTS_DIR = Path("results")


def ensure_results_dir():

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def timestamp():

    return datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )


def export_json(hosts):

    ensure_results_dir()

    path = (
        RESULTS_DIR
        / f"network_{timestamp()}.json"
    )

    data = {
        "tool": "NetScope",
        "export_time": datetime.now().isoformat(
            timespec="seconds"
        ),
        "hosts": hosts,
    }

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False,
        )

    console.print(
        f"[green]✓ JSON exported:[/green] {path}"
    )


def export_csv(hosts):

    ensure_results_dir()

    path = (
        RESULTS_DIR
        / f"network_{timestamp()}.csv"
    )

    with path.open(
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
                "status",
            ],
        )

        writer.writeheader()
        writer.writerows(hosts)

    console.print(
        f"[green]✓ CSV exported:[/green] {path}"
    )


def collect_evidence(
    target,
    assessment,
):

    ensure_results_dir()

    path = (
        RESULTS_DIR
        / f"evidence_{timestamp()}.json"
    )

    evidence = {
        "tool": "NetScope",
        "collection_time": datetime.now().isoformat(
            timespec="seconds"
        ),
        "target": target,
        "assessment": assessment,
    }

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            evidence,
            file,
            indent=4,
            ensure_ascii=False,
        )

    console.print(
        f"[green]✓ Evidence saved:[/green] {path}"
    )


def generate_report(
    target,
    assessment,
    blocked,
):

    ensure_results_dir()

    path = (
        RESULTS_DIR
        / f"incident_report_{timestamp()}.json"
    )

    report = {
        "report_type": "Network Security Assessment",
        "generated_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "target": target,
        "assessment": assessment,
        "contained_devices": blocked,
    }

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
        )

    console.print(
        f"[green]✓ Incident report saved:[/green] {path}"
    )
