#!/usr/bin/env python3

"""Collect Hetzner SSH journal events into local Splunk HEC."""

import hashlib
import http.client
import ipaddress
import json
import os
import re
import shlex
import ssl
import subprocess
from pathlib import Path


HOME = Path.home()

INVENTORY = Path(
    "/mnt/hyperV/projects/vps-infrastructure/ansible/inventory.ini"
)

CONFIG = HOME / ".config/labops-splunk/private"

TOKEN_FILE = CONFIG / "hec-vps.token"
CA_FILE = CONFIG / "hec-ca.pem"
PIN_FILE = CONFIG / "hec-cert.sha256"
STATE_FILE = CONFIG / "hetzner-ssh.cursor"

HEC_HOST = "127.0.0.1"
HEC_PORT = 18088
HEC_INDEX = "labops_vps"

ANSIBLE_HOST = "staging-vps"


def get_host_config():
    result = subprocess.run(
        [
            "ansible-inventory",
            "-i",
            str(INVENTORY),
            "--host",
            ANSIBLE_HOST,
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    return json.loads(result.stdout)


def read_cursor():
    if STATE_FILE.exists():
        return STATE_FILE.read_text().strip()

    return None


def save_cursor(cursor):
    temporary = STATE_FILE.with_suffix(".cursor.tmp")

    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )

    with os.fdopen(fd, "w") as stream:
        stream.write(cursor + "\n")
        stream.flush()
        os.fsync(stream.fileno())

    os.replace(temporary, STATE_FILE)


def retrieve_journal():
    config = get_host_config()

    host = config["ansible_host"]
    user = config.get("ansible_user", "root")
    port = str(config.get("ansible_port", 22))

    ssh_command = [
        "ssh",
        "-p",
        port,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=10",
    ]

    identity = (
        config.get("ansible_ssh_private_key_file")
        or config.get("ansible_private_key_file")
    )

    if identity:
        ssh_command.extend([
            "-i",
            str(Path(identity).expanduser()),
        ])

    journal_command = [
        "journalctl",
        "-u",
        "ssh.service",
        "--no-pager",
        "--output=json",
    ]

    cursor = read_cursor()

    if cursor:
        journal_command.append(
            "--after-cursor=" + cursor
        )
    else:
        journal_command.extend([
            "--since",
            "24 hours ago",
        ])

    ssh_command.extend([
        f"{user}@{host}",
        shlex.join(journal_command),
    ])

    result = subprocess.run(
        ssh_command,
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )

    events = []

    for line in result.stdout.splitlines():
        if line.strip():
            events.append(json.loads(line))

    return events


def classify_event(message):
    if "Failed password" in message:
        return "ssh_authentication_failure"

    if "Invalid user" in message:
        return "ssh_invalid_user"

    if "Accepted publickey" in message:
        return "ssh_authentication_success"

    if "Accepted password" in message:
        return "ssh_authentication_success"

    if "Disconnected" in message:
        return "ssh_disconnection"

    if "Connection closed" in message:
        return "ssh_connection_closed"

    if "Connection reset" in message:
        return "ssh_connection_reset"

    if "banner exchange" in message:
        return "ssh_banner_error"

    return "ssh_service_event"


def extract_source_ip(message):
    match = re.search(
        r"\b(?:from|by) \[?([0-9a-fA-F:.]+)\]?(?=\s|$)",
        message,
    )

    if not match:
        return None

    try:
        return str(
            ipaddress.ip_address(match.group(1))
        )
    except ValueError:
        return None


AUTH_SUCCESS_PATTERN = re.compile(
    r"^Accepted\s+(?P<auth_method>publickey|password)"
    r"\s+for\s+(?P<username>\S+)"
    r"\s+from\s+\S+"
    r"\s+port\s+\d+\s+ssh2"
    r"(?:\s*:\s*(?P<key_type>\S+)"
    r"\s+(?P<key_fingerprint>SHA256:[A-Za-z0-9+/=]+))?"
)


def extract_auth_details(message):
    match = AUTH_SUCCESS_PATTERN.match(message)

    if not match:
        return {}

    return {
        key: value
        for key, value in match.groupdict().items()
        if value is not None
    }


def normalize_event(record):
    message = record.get("MESSAGE", "")

    event = {
        "event_type": classify_event(message),
        "message": message,
        "service": "ssh",
        "source_system": "hetzner_staging",
        "synthetic": False,
        "journal_cursor": record.get("__CURSOR"),
        "journal_priority": record.get("PRIORITY"),
    }

    if event["event_type"] == "ssh_authentication_success":
        event.update(extract_auth_details(message))

    source_ip = extract_source_ip(message)

    if source_ip:
        event["src_ip"] = source_ip

    timestamp = record.get(
        "__REALTIME_TIMESTAMP"
    )

    if timestamp:
        event_time = int(timestamp) / 1_000_000
    else:
        raise ValueError(
            "Journal event missing original timestamp"
        )

    return {
        "time": event_time,
        "host": record.get(
            "_HOSTNAME",
            ANSIBLE_HOST,
        ),
        "source": "journal:ssh",
        "sourcetype": "_json",
        "index": HEC_INDEX,
        "event": event,
    }


def submit_hec(payload):
    token = TOKEN_FILE.read_text().strip()
    expected_pin = PIN_FILE.read_text().strip()

    context = ssl.create_default_context(
        cafile=str(CA_FILE)
    )

    # Local Splunk default certificate lacks a
    # verified localhost identity. Check its CA
    # chain and explicitly pin its leaf certificate.
    context.check_hostname = False

    connection = http.client.HTTPSConnection(
        HEC_HOST,
        HEC_PORT,
        context=context,
        timeout=15,
    )

    try:
        connection.connect()

        actual_pin = hashlib.sha256(
            connection.sock.getpeercert(
                binary_form=True
            )
        ).hexdigest()

        if actual_pin != expected_pin:
            raise ssl.SSLError(
                "HEC certificate fingerprint mismatch"
            )

        connection.request(
            "POST",
            "/services/collector/event",
            body=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Splunk {token}",
                "Content-Type": "application/json",
            },
        )

        response = connection.getresponse()

        body = response.read().decode()

        if response.status != 200:
            raise RuntimeError(
                f"HEC HTTP {response.status}: {body}"
            )

        result = json.loads(body)

        if result.get("code") != 0:
            raise RuntimeError(
                f"HEC rejected event: {result}"
            )

    finally:
        connection.close()


def main():
    events = retrieve_journal()

    print(
        f"Retrieved {len(events)} SSH journal events"
    )

    accepted = 0

    for record in events:
        cursor = record.get("__CURSOR")

        if not cursor:
            raise ValueError(
                "Journal event missing cursor"
            )

        payload = normalize_event(record)

        submit_hec(payload)

        # Advance only after HEC accepts the event.
        save_cursor(cursor)

        accepted += 1

    print(
        f"Accepted by Splunk HEC: {accepted}"
    )

    print(
        "Destination index: labops_vps"
    )


if __name__ == "__main__":
    main()
