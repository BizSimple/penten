# Restricted Container Run — GitHub Action

A composite action that runs a command inside a **locked-down Docker container**.
The container is isolated on its own bridge network and, by default, has **no
network access at all** — you explicitly allow a specific set of **host TCP
ports** it may reach. After the main command, an *output command* runs and its
combined stdout/stderr is posted as a **new GitHub issue**.

## Inputs

| Input            | Required | Description |
|------------------|----------|-------------|
| `image`          | yes      | Docker image name (e.g. `alpine:3.20`, `node:22-slim`). |
| `command`        | yes      | Command run inside the container (via `/bin/sh -c`). |
| `project-dir`    | yes      | Shared project directory, mounted at `/workspace`. Relative paths resolve against the calling workflow's workspace. |
| `output-command` | yes      | Command run after `command`; its output is posted as an issue. |
| `github-token`   | yes      | Token with `issues: write`, used to create the issue. |
| `host-ports`     | no       | Comma-separated host TCP ports the container may reach (e.g. `"5432,8080"`). Empty = no network. |
| `run-as-user`    | no       | UID or UID:GID the command runs as. Default `1000:1000` (unprivileged). Use `0:0` only if you truly need root. |
| `project-write`  | no       | Mount `/workspace` writable. Default `false` (read-only). |
| `read-only-root` | no       | Read-only container root filesystem with a tmpfs `/tmp`. Default `true`. |
| `memory`         | no       | Hard memory limit (e.g. `512m`, `2g`). Default `2g`. |
| `cpus`           | no       | CPU quota (e.g. `1`, `1.5`). Default `2`. |
| `issue-title`    | no       | Title for the created issue. Defaults to a workflow/run label. |

## Outputs

| Output         | Description                          |
|----------------|--------------------------------------|
| `issue-url`    | URL of the created issue.            |
| `issue-number` | Number of the created issue.         |
| `exit-code`    | Exit code of the main command.       |

## How the restriction works

- The container runs on a **dedicated bridge network** with inter-container
  communication disabled (`enable_icc=false`).
- An `iptables` rule in the `DOCKER-USER` chain **drops all forwarded egress**
  from that subnet — no internet, no other networks.
- Host-bound traffic is **default-deny** (`INPUT` drop for the subnet); one
  `ACCEPT` rule per allowed port opens exactly those host TCP ports.
- The container drops all Linux capabilities (`--cap-drop ALL`) and forbids
  privilege escalation (`--security-opt no-new-privileges`), which also
  neutralises any setuid binary reachable through the bind mount.
- It runs as an **unprivileged user** (`run-as-user`, default `1000:1000`), with
  a **read-only root filesystem** (writes go to a 64 MB `noexec` tmpfs at `/tmp`)
  and the project **mounted read-only** unless `project-write: true`.
- It uses Docker's default **private pid / ipc / network namespaces** — the host
  namespaces are never shared (`--pid=host` / `--ipc=host` / `--network=host`
  are not used), and there is no Docker socket mount.
- **Memory, CPU, PID and file-descriptor limits** cap the blast radius so a
  runaway or malicious container cannot exhaust the runner.
- Inputs that flow into the `docker run` flags (`run-as-user`, `memory`, `cpus`)
  are strictly validated, preventing extra Docker flags from being injected.
- Inside the container the host is reachable as **`host.local`** (also exported
  as the `$HOST_IP` environment variable).

> **Data-exposure note:** the *output command's* stdout/stderr is posted to a
> GitHub issue. Do not run output commands that print secrets, and remember the
> issue is visible to anyone who can see the repository. The container is never
> given the `github-token`.

> Requires a Linux runner with `sudo iptables` available (e.g.
> `ubuntu-latest`). Firewall rules and the network are removed on cleanup,
> even if earlier steps fail.

## Usage

```yaml
permissions:
  contents: read
  issues: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/penten@main
        with:
          image: alpine:3.20
          command: "ls -la /workspace && echo prepared"
          project-dir: .
          output-command: "nc -zv host.local 5432 || echo 'db not reachable'"
          host-ports: "5432"
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

If your command needs to write to the project or install packages at runtime,
opt out of the stricter defaults explicitly:

```yaml
        with:
          # ...
          project-write: "true"     # writable /workspace bind mount
          read-only-root: "false"   # allow apk/apt installs into the image
```

See [`.github/workflows/example.yml`](../.github/workflows/example.yml) for a
runnable example that spins up a Postgres service and lets the container reach
it on port 5432.
