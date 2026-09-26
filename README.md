# Splunk LabOps — Security Telemetry Engineering

A Splunk Enterprise and Python security telemetry pipeline connecting a remote Hetzner Linux VPS with a Debian workstation for centralized collection and investigation of authentication events.

> **Operational pipeline (2026-09-26):** Splunk Enterprise 10.4.3 indexes real SSH journal events collected from a Hetzner VPS by a Python collector on a five-minute systemd user timer. Scoped HTTPS HEC tokens, incremental journal cursors, preserved event timestamps, and nine automated collector tests support the implementation.

## Project overview

I deployed Splunk Enterprise on my Debian workstation and built a Python security telemetry collector for a remote Hetzner VPS. The collector retrieves OpenSSH journal records over key-authenticated SSH, normalizes them into structured events, and submits them through Splunk's authenticated HTTPS Event Collector (HEC) for SPL-based investigation. A systemd user timer runs the collection every five minutes; persistent journal cursors support incremental processing and recovery.

The project brings together Splunk administration, Linux security logging, Python automation, API integration, and testable operational behavior. The deployed product is **Splunk Enterprise**.

## Architecture

```text
Hetzner staging VPS (Debian 13)
    |
    | OpenSSH / ssh.service systemd journal
    | workstation-initiated SSH, port 4222
    v
Debian 12 workstation
    |
    +-- systemd user timer (every five minutes)
    |     +-- Python SSH journal collector
    |           +-- remote journal cursor / original timestamps
    |           +-- event classification / source IP extraction
    |           +-- CA-verified and pinned localhost HEC TLS
    |           v
    |       Splunk HEC: https://127.0.0.1:18088
    |           +-- labops_vps
    |
    +-- Splunk Enterprise 10.4.3 (Docker Compose)
    |     +-- Splunk Web: http://127.0.0.1:18000
    |     +-- configuration: /mnt/labops-splunk/etc
    |     +-- indexes/runtime data: /mnt/labops-splunk/var
    |     +-- labops_local
    |     +-- labops_aws (configured; AWS ingestion not active)
    |
    +-- Porter / Prometheus / Grafana (separate deployment)
```

Only Splunk Web and HEC are host-published, both on workstation loopback. The workstation pulls logs from Hetzner over its existing key-authenticated SSH connection. There is no public Splunk listener and no Splunk HEC credential on the VPS. The internal Docker-exposed Splunk ports are not mapped to host interfaces.

## Deployment configuration

| Item | Value |
| --- | --- |
| Host | Debian 12 workstation |
| Container image | `splunk/splunk:10.4.3` |
| Docker Compose project | `labops-splunk` |
| Container name | `labops-splunk-splunk-1` |
| Compose file | `~/.config/labops-splunk/compose.yaml` |
| Private environment file | `~/.config/labops-splunk/compose.env` — **never commit** |
| Persistent Splunk configuration | `/mnt/labops-splunk/etc` |
| Persistent Splunk runtime/index data | `/mnt/labops-splunk/var` |
| Web endpoint | `http://127.0.0.1:18000` (verified) |
| HEC endpoint | `https://127.0.0.1:18088` (verified; loopback only) |
| Container limits | 8 GiB memory; 4 CPUs |
| Docker JSON logs | 10 MB/file × 3 rotated files |
| Initial total-footprint planning target | Approximately 20 GB; **not an enforced disk quota** |

**Storage design:** `/mnt/labops-splunk` resides on the workstation's existing LUKS-encrypted ext4 **root filesystem** (`/dev/mapper/luksroot`); `/mnt` is not a separate disk. After the smoke test, the persistent configuration directory measured about **1.2 GB**, runtime/index data about **1.4 GB**, and the root filesystem had about **149 GB available** (69% used). Docker image and build-cache usage are additional. Index size limits are retention targets, **not** a hard quota on the whole deployment.

## Developer License

The **Splunk Developer Personal License** is installed and marked **valid** in Splunk Web, with an effective daily volume of **10,240 MB (10 GB)** and a displayed expiration of **March 25, 2027**. This is an ingestion allowance, not a disk quota or an expectation of 10 GB of logs per day. Keep license files, account email, credentials, and tokens out of Git.

## First-run failure and resolution (2026-09-25)

The first startup repeatedly failed at Ansible's `set version fact` task because the startup identity could not read `/opt/splunk/etc/splunk.version`.

Observed diagnostics:

- The unmounted image has the original version file at `/opt/splunk-etc/splunk.version`; the startup script copies that backup into `/opt/splunk/etc`.
- `/mnt/labops-splunk/etc/splunk.version` **had been copied successfully**, but `/mnt/labops-splunk/etc` was `0750`, owned by UID/GID `41812` (Splunk).
- A diagnostic container ran as `uid=999(ansible)` and reported `NOT READABLE` for the file, proving a directory traversal/read-permission issue.
- The operator ran `sudo chmod 755 /mnt/labops-splunk/etc` **only on the top-level configuration directory**, retaining ownership and individual file permissions.
- The existing container was restarted without deleting the configuration, indexes, or private administrator password. Ansible then passed `set version fact`, started Splunk through its CLI, and completed with `ok=87`, `changed=6`, `failed=0`.

The Splunk Web login and sustained `docker ps` health check were subsequently verified. Do not recursively change permissions on `etc` or expose secret-bearing files.

## Index design and first ingestion test

Local overrides live at `$SPLUNK_HOME/etc/system/local/indexes.conf` in the container, backed by `/mnt/labops-splunk/etc/system/local/indexes.conf` on the workstation. The operator verified the effective configuration with `splunk btool indexes list` executed as the Splunk UID (`41812`), rather than relying only on the file contents.

| Index | Maximum indexed size | Time-based retention | Intended use |
| --- | ---: | ---: | --- |
| `labops_local` | 1,024 MB | Up to 7 days | Workstation and local test events |
| `labops_vps` | 2,048 MB | Up to 14 days | Active Hetzner SSH telemetry; more sources planned |
| `labops_aws` | 2,048 MB | Up to 14 days | Planned disposable AWS lab telemetry |

The 16 existing Splunk indexes were also assigned smaller per-index limits. The combined **configured index size targets total 12 GiB**. Data can be retired earlier when an index reaches its size limit; absent a frozen archive, retired events are deleted. Configuration, logs, Docker layers, and search artifacts consume additional storage.

**Smoke test (2026-09-26):** A single synthetic JSON file, `labops-smoke.json`, was uploaded through the Splunk Add Data wizard with `_json` source type, host `local_workstation`, and destination index `labops_local`. Splunk extracted the UTC timestamp and JSON fields. Search & Reporting returned **one matching event** for:

```spl
index=labops_local "labops_smoke_test"
```

This initial test established the ingestion and search path before programmatic HEC and live Hetzner SSH journal collection were added.

## HEC ingestion and Hetzner SSH journal collector

### Dedicated HEC credentials

HTTP Event Collector is enabled over HTTPS on workstation loopback (`127.0.0.1:18088`). Two tokens separate ingestion scope:

| Token name | Allowed and default index | Verified evidence |
| --- | --- | --- |
| `labops-local-hec` | `labops_local` | Indexed and searched a synthetic authentication failure |
| `labops-vps-hec` | `labops_vps` | Indexed and searched a synthetic connectivity event |

Both tokens use the `_json` source type. Token values are saved outside this repository in private, mode-`0600` files under `~/.config/labops-splunk/private/`. Credentials, license files, raw journal exports, and Splunk runtime data stay outside the Git checkout.

The synthetic searches were:

```spl
index=labops_local test_id="labops_hec_smoke_test"
```

```spl
index=labops_vps test_id="labops_vps_hec_smoke"
```

![Synthetic local HEC event](docs/screenshots/05-local-hec-ingestion.png)

![Synthetic VPS-index HEC event](docs/screenshots/06-vps-hec-ingestion.png)

### Real SSH telemetry

[`collectors/hetzner_journal.py`](collectors/hetzner_journal.py) retrieves JSON records from Hetzner's `ssh.service` journal using the existing Ansible inventory and key-authenticated SSH connection. The initial run collects up to the preceding 24 hours; subsequent runs pass the last saved `__CURSOR` to `journalctl --after-cursor`.

The collector preserves `__REALTIME_TIMESTAMP`, records journal cursors, classifies common OpenSSH messages, extracts IPv4/IPv6 source addresses where present, and sends events into `labops_vps` through the local HEC endpoint. It uses the configured Splunk CA and a pinned leaf certificate; hostname verification is disabled for the default Splunk certificate, which does not establish a verified `127.0.0.1` identity. A dedicated certificate with a localhost IP Subject Alternative Name remains a hardening improvement. A certificate change requires explicit operator review rather than automatic repinning.

Private state and trust files, kept outside Git:

```text
~/.config/labops-splunk/private/hec-vps.token
~/.config/labops-splunk/private/hec-ca.pem
~/.config/labops-splunk/private/hec-cert.sha256
~/.config/labops-splunk/private/hetzner-ssh.cursor
```

Run a manual collection from the checkout:

```bash
python3 collectors/hetzner_journal.py
```

Search real events in Splunk:

```spl
index=labops_vps source="journal:ssh"
| table _time host event_type src_ip message
| sort - _time
```

Check for duplicated journal cursors:

```spl
index=labops_vps source="journal:ssh"
| stats count as copies by journal_cursor
| where copies > 1
```

The first two manual runs produced 16 indexed SSH events, with no duplicated cursors observed. Additional manual and timer-triggered runs ingested newer records. A returned HTTP 200 / HEC code 0 means the event was accepted, not that completed indexing is guaranteed: indexer acknowledgment is disabled. The pipeline has at-least-once submission semantics, so a crash after HEC acceptance but before writing the cursor can cause duplicates. Recovery is also bounded by journal retention on the VPS.

### Automatic collection and tests

The installed user units are tracked in [`systemd/`](systemd/):

- `labops-hetzner.service`: `Type=oneshot` Python collector run as the workstation user.
- `labops-hetzner.timer`: five-minute calendar schedule.

The service file uses workstation-specific absolute paths; adapt them before deploying elsewhere. The first timer-triggered run was verified on September 25, 2026 at 9:25 PM EDT: three SSH journal records were accepted by HEC and the timer scheduled its next activation for 9:30 PM. At that time `Linger=no`; continued operation after the last logout has not been verified.

```bash
python3 -m unittest discover -s tests -v
systemctl --user status labops-hetzner.timer --no-pager
systemctl --user list-timers --all | grep labops
journalctl --user -u labops-hetzner.service -n 30 --no-pager
```

Nine unit tests pass for classification, source-IP parsing (including IPv6), timestamp preservation, and not advancing the cursor after failed HEC submission.

A sanitized live-telemetry screenshot will be added after review. Raw VPS events and credentials remain outside the repository.

## Deployment evidence

The deployment screenshots document the platform setup and initial ingestion checks; HEC ingestion screenshots follow in the collector section above.

### 1. Healthy container and effective index settings

At capture time, the Docker container reported `healthy` and only Splunk Web was host-published. HEC was subsequently published on loopback at `127.0.0.1:18088`. The CLI output independently confirms the three LabOps size and retention settings.

![Healthy Splunk Docker container and effective LabOps index configuration](docs/screenshots/01-docker-health.png)

### 2. Dedicated index storage configuration

Splunk Web shows the `labops_vps` index with a **2 GB** maximum and a **128 MB** bucket-size target. The 14-day time limit was verified separately through `btool`.

![Splunk index configuration showing the labops_vps storage policy](docs/screenshots/02-index-configuration.png)

### 3. Managed index inventory

The Indexes screen shows **19 indexes**, including `labops_aws`, `labops_local`, and `labops_vps`, with the configured per-index maximum sizes. At capture time, `labops_local` contained one test event; the VPS and AWS indexes were empty. The VPS index now contains real SSH events.

![Splunk index inventory with three dedicated LabOps indexes](docs/screenshots/03-managed-indexes.png)

### 4. Indexed JSON event and SPL verification

Search & Reporting returns the synthetic event from `labops_local`, showing the extracted JSON fields and metadata (`host=local_workstation`, `sourcetype=_json`).

![Successful LabOps JSON smoke-test event search in Splunk](docs/screenshots/04-json-ingestion-search.png)

## Operator commands

Run from the home workstation:

```bash
cd "$HOME/.config/labops-splunk"

# Check all containers without revealing secrets
docker ps -a --filter name=labops-splunk \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'

# Read recent logs
docker compose --env-file compose.env -p labops-splunk \
  logs --tail=100 splunk

# Validate Compose without printing the interpolated password
docker compose --env-file compose.env -p labops-splunk \
  config --quiet

# Measure Splunk persistent data and remaining filesystem capacity
sudo du -sh /mnt/labops-splunk
df -hT /mnt/labops-splunk
```

Do **not** publish `docker compose config` output, as interpolation can expose secrets. Do not commit `compose.env`, Splunk `etc/` or `var/`, logs, credentials, tokens, license files, or raw VPS/security events.

## Engineering milestones

- [x] Inspect workstation capacity and existing services.
- [x] Pull Splunk Enterprise 10.4.3 and create isolated Compose deployment.
- [x] Generate an administrator password in a private, mode-0600 environment file.
- [x] Bind persistent Splunk directories to encrypted ext4 storage.
- [x] Diagnose and resolve first-run provisioning (Ansible `failed=0`).
- [x] Verify healthy container and Splunk Web login.
- [x] Verify the active Developer Personal License (10 GB/day).
- [x] Configure and verify index size/retention limits **before continuous ingestion**.
- [x] Verify localhost-only host port publication and measure root filesystem capacity.
- [x] Upload a controlled local JSON event and retrieve it with SPL.
- [x] Configure authenticated localhost-only HEC with separate local and VPS tokens.
- [x] Index and search synthetic HEC events in both dedicated indexes.
- [x] Collect and search genuine Hetzner SSH journal events over SSH.
- [x] Preserve original journal timestamps and maintain an incremental cursor.
- [x] Verify no duplicate cursors in the first 16 indexed SSH events.
- [x] Pass nine automated collector tests.
- [x] Verify the five-minute systemd user timer triggers collection.
- [ ] Validate unattended operation after logout and longer connectivity gaps.
- [ ] Add Fail2Ban and Apache telemetry.
- [ ] Build SPL detections, dashboards, and alerting.
- [ ] Optionally instrument disposable AWS lab runs.
- [ ] Publish a sanitized live-telemetry screenshot.

## Repository contents

The repository tracks the Python collector, systemd units, automated tests, index configuration and deployment evidence. Runtime files, secrets, license material, and raw security logs are maintained outside the checkout. The Splunk LabOps repository complements my separate infrastructure automation and Porter projects.
