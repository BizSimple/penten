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
- The container drops all Linux capabilities (`--cap-drop ALL`), forbids
  privilege escalation (`--security-opt no-new-privileges`) and is PID-limited.
- Inside the container the host is reachable as **`host.local`** (also exported
  as the `$HOST_IP` environment variable).

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
          command: "apk add --no-cache curl && echo prepared"
          project-dir: .
          output-command: "nc -zv host.local 5432 || echo 'db not reachable'"
          host-ports: "5432"
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

See [`.github/workflows/example.yml`](../.github/workflows/example.yml) for a
runnable example that spins up a Postgres service and lets the container reach
it on port 5432.
