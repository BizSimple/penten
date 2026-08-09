# Restricted Container Run — GitHub Action

A composite action that runs a command inside a **locked-down Docker container**.
The container is isolated on its own bridge network and, by default, has **no
outbound network access** (external DNS included) — you explicitly allow a
specific set of **host TCP ports** it may reach. After the main command, an
*output command* runs and its combined stdout/stderr is posted as a **new GitHub
issue**.

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

- The container runs on a **dedicated bridge network** (subnet allocated by
  Docker, so concurrent jobs never collide) with inter-container communication
  disabled (`enable_icc=false`).
- An `iptables` rule in the `DOCKER-USER` chain **drops all forwarded egress**
  from that subnet — no internet, no other networks. Every rule is tagged with
  the network name and removed by that tag on cleanup.
- **External DNS is black-holed** (`--dns 0.0.0.0`). Docker's embedded resolver
  runs in the host network namespace and so bypasses the egress drop; without
  this it is a data-exfiltration channel even with `host-ports` empty. Internal
  name lookups and `host.local` (`/etc/hosts`) still work.
- Host-bound traffic is **default-deny** (`INPUT` drop for the subnet); one
  `ACCEPT` rule per allowed port opens exactly those host TCP ports.
- The container drops all Linux capabilities (`--cap-drop ALL`) and forbids
  privilege escalation (`--security-opt no-new-privileges`). Because
  `CAP_DAC_OVERRIDE` is dropped, even `run-as-user: "0:0"` (root inside the
  container) is still subject to normal file-permission checks on the bind
  mount — root inside is **not** root on the host — and any setuid binary
  reachable through the mount is neutralised.
- It runs as an **unprivileged user** (`run-as-user`, default `1000:1000`), with
  a **read-only root filesystem** (writes go to a 64 MB `noexec` tmpfs at `/tmp`)
  and the project **mounted read-only** unless `project-write: true`.
- The resolved `project-dir` (symlinks included) must stay **inside
  `$GITHUB_WORKSPACE`**; paths that escape it (`/`, `../..`, a symlink to
  `/home/runner`) are rejected, so host credentials and caches cannot be mounted
  into the container.
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

### Operational guidance for self-hosted runners

- This action edits the host's `INPUT` chain. Prefer **ephemeral runners**; on a
  long-lived runner the cleanup removes only this run's tagged rules, but a
  crashed runner could still leave rules behind.
- **Never** mount the Docker socket (`/var/run/docker.sock`) into the container —
  it is equivalent to host root and defeats every control here.
- Keep `project-write: "true"` off unless a step truly needs it: a writable
  checkout combined with any later step that executes repo content is host code
  execution.
- **Pin images by digest** for untrusted or supply-chain-sensitive use, e.g.
  `alpine:3.20@sha256:…` — a bare tag like `alpine:3.20` is mutable and can be
  repointed at a different image.

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
