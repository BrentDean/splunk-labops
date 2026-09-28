#!/usr/bin/env python3

"""Incrementally collect Hetzner Fail2Ban logs into Splunk."""

import base64
import json
import os
import re
import shlex
import subprocess
from datetime import datetime
from pathlib import Path

import hetzner_journal as shared


STATE_FILE = (
    Path.home()
    / ".config/labops-splunk/private/hetzner-fail2ban-state.json"
)

MAX_LOG_BYTES = 4 * 1024 * 1024

REMOTE_SNAPSHOT_SCRIPT = r'''
import base64
import json
import os
import sys

MAX_BYTES = 4 * 1024 * 1024

def snapshot(path):
    try:
        with open(path, "rb") as stream:
            info = os.fstat(stream.fileno())

            if info.st_size > MAX_BYTES:
                raise RuntimeError(
                    f"{path} exceeds collection size limit"
                )

            content = stream.read(MAX_BYTES + 1)

            if len(content) > MAX_BYTES:
                raise RuntimeError(
                    f"{path} grew beyond collection size limit"
                )

            return {
                "identity": f"{info.st_dev}:{info.st_ino}",
                "data": base64.b64encode(
                    content
                ).decode("ascii"),
            }

    except FileNotFoundError:
        return None


result = {
    "current": snapshot("/var/log/fail2ban.log"),
    "previous": snapshot("/var/log/fail2ban.log.1"),
}

print(json.dumps(result))
'''


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2},\d{3})\s+"
    r"(?P<component>\S+)\s+"
    r"\[(?P<pid>\d+)\]:\s+"
    r"(?P<level>\w+)\s+"
    r"(?P<message>.*)$"
)

ACTION_PATTERN = re.compile(
    r"^\[(?P<jail>[^\]]+)\]\s+"
    r"(?P<action>Ban|Unban|Found)\s+"
    r"(?P<ip>\S+)"
)


def retrieve_snapshot():
    config = shared.get_host_config()

    host = config["ansible_host"]
    user = config.get("ansible_user", "root")
    port = str(config.get("ansible_port", 22))

    command = [
        "ssh",
        "-T",
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
        command.extend([
            "-i",
            str(Path(identity).expanduser()),
        ])

    command.extend([
        f"{user}@{host}",
        shlex.join(["python3", "-"]),
    ])

    result = subprocess.run(
        command,
        input=REMOTE_SNAPSHOT_SCRIPT,
        capture_output=True,
        text=True,
        check=True,
        timeout=90,
    )

    return json.loads(result.stdout)


def read_state():
    if not STATE_FILE.exists():
        return None

    return json.loads(STATE_FILE.read_text())


def save_state(identity, offset):
    state = {
        "identity": identity,
        "offset": offset,
    }

    temporary = STATE_FILE.with_suffix(".tmp")

    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )

    with os.fdopen(fd, "w") as stream:
        json.dump(state, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())

    os.replace(temporary, STATE_FILE)


def normalize_line(line):
    match = LOG_PATTERN.match(line)

    if not match:
        raise ValueError(
            "Unrecognized Fail2Ban log format"
        )

    fields = match.groupdict()

    timestamp = datetime.strptime(
        fields["timestamp"],
        "%Y-%m-%d %H:%M:%S,%f",
    )

    # The VPS uses UTC. The log timestamp has no
    # explicit timezone, so interpret it as UTC.
    from datetime import timezone

    timestamp = timestamp.replace(
        tzinfo=timezone.utc
    )

    message = fields["message"]

    event = {
        "event_type": "fail2ban_service_event",
        "message": message,
        "component": fields["component"],
        "level": fields["level"],
        "service": "fail2ban",
        "source_system": "hetzner_staging",
        "synthetic": False,
    }

    action = ACTION_PATTERN.match(message)

    if action:
        action_fields = action.groupdict()

        event["jail"] = action_fields["jail"]

        try:
            import ipaddress

            event["src_ip"] = str(
                ipaddress.ip_address(
                    action_fields["ip"]
                )
            )
        except ValueError:
            pass

        classification = {
            "Found": "fail2ban_failure_detected",
            "Ban": "fail2ban_ban",
            "Unban": "fail2ban_unban",
        }

        event["event_type"] = classification[
            action_fields["action"]
        ]

    elif "rollover performed" in message:
        event["event_type"] = "fail2ban_log_rollover"

    elif fields["level"] in {
        "ERROR",
        "CRITICAL",
    }:
        event["event_type"] = "fail2ban_error"

    return {
        "time": timestamp.timestamp(),
        "host": "staging-vps",
        "source": "fail2ban:log",
        "sourcetype": "_json",
        "index": "labops_vps",
        "event": event,
    }


def decode_snapshot(snapshot):
    if snapshot is None:
        return None

    return {
        "identity": snapshot["identity"],
        "data": base64.b64decode(
            snapshot["data"],
            validate=True,
        ),
    }


def process_file(snapshot, offset):
    data = snapshot["data"]

    if offset > len(data):
        raise RuntimeError(
            "Fail2Ban log was truncated; "
            "collection state requires inspection"
        )

    position = offset
    accepted = 0

    for raw_line in data[offset:].splitlines(
        keepends=True
    ):
        # Leave incomplete lines for the next run.
        if not raw_line.endswith(b"\n"):
            break

        line = raw_line.decode(
            "utf-8",
            errors="replace",
        ).rstrip("\r\n")

        if line:
            payload = normalize_line(line)

            # Reuse the existing authenticated,
            # certificate-pinned HEC client.
            shared.submit_hec(payload)

            accepted += 1

        position += len(raw_line)

        # Only advance after successful submission.
        save_state(
            snapshot["identity"],
            position,
        )

    return accepted


def main():
    snapshots = retrieve_snapshot()

    current = decode_snapshot(
        snapshots["current"]
    )

    previous = decode_snapshot(
        snapshots["previous"]
    )

    if current is None:
        raise RuntimeError(
            "Fail2Ban log does not exist"
        )

    state = read_state()

    accepted = 0

    if state is None:
        print(
            "Initial collection: current Fail2Ban log"
        )

        save_state(
            current["identity"],
            0,
        )

        accepted += process_file(
            current,
            0,
        )

    elif state["identity"] == current["identity"]:
        accepted += process_file(
            current,
            state["offset"],
        )

    elif (
        previous is not None
        and state["identity"]
        == previous["identity"]
    ):
        print(
            "Fail2Ban log rotation detected"
        )

        accepted += process_file(
            previous,
            state["offset"],
        )

        save_state(
            current["identity"],
            0,
        )

        accepted += process_file(
            current,
            0,
        )

    else:
        raise RuntimeError(
            "Previous Fail2Ban log identity "
            "not found. Possible missed rotation; "
            "collection state requires inspection."
        )

    print(
        f"Accepted by Splunk HEC: {accepted}"
    )

    print(
        "Destination index: labops_vps"
    )


if __name__ == "__main__":
    main()
