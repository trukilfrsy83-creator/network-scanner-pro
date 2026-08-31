import platform
import subprocess
from ipaddress import ip_interface


def get_local_network():

    system = platform.system()

    if system == "Linux":

        try:
            output = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", "up"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout

            for line in output.splitlines():

                parts = line.split()

                if len(parts) < 4:
                    continue

                interface = parts[1]
                address = parts[3]

                if address.startswith("127."):
                    continue

                info = ip_interface(address)

                return (
                    interface,
                    str(info.ip),
                    str(info.network),
                )

        except Exception:
            pass

    elif system == "Darwin":

        try:
            output = subprocess.run(
                ["ifconfig"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout

            current_interface = None

            for line in output.splitlines():

                if line and not line.startswith((" ", "\t")):
                    current_interface = line.split(":")[0]

                if "inet " in line:

                    parts = line.split()

                    if len(parts) < 2:
                        continue

                    ip = parts[1]

                    if ip == "127.0.0.1":
                        continue

                    return (
                        current_interface,
                        ip,
                        "Detected network",
                    )

        except Exception:
            pass

    elif system == "Windows":

        try:
            output = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout

            ip = None
            mask = None

            for line in output.splitlines():

                if "IPv4 Address" in line:
                    ip = line.split(":")[-1].strip()

                elif "Subnet Mask" in line:
                    mask = line.split(":")[-1].strip()

                if ip and mask:

                    prefix = sum(
                        bin(int(x)).count("1")
                        for x in mask.split(".")
                    )

                    info = ip_interface(
                        f"{ip}/{prefix}"
                    )

                    return (
                        "Windows Adapter",
                        ip,
                        str(info.network),
                    )

        except Exception:
            pass

    return None, None, None
