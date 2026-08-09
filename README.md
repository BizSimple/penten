# penten

**Run commands inside a locked-down Docker container from CI — no outbound network by default — and post the output as a GitHub issue.**

`penten` is a GitHub [composite action](https://docs.github.com/actions/sharing-automations/creating-a-composite-action) built for running untrusted or security-sensitive commands (scanners, pentests, ad-hoc probes) inside a sandbox you control. The container is isolated on its own bridge network with **no internet access and external DNS black-holed**; you explicitly allow only the specific **host TCP ports** it may reach. After the main command runs, a second *output command* runs and its combined output is posted to a **new GitHub issue** so results are captured without giving the container any credentials.

> **Name:** _pen_ (penetration) _ten_ — local/CI pentesting in a tin can.

---

## Why

CI jobs routinely run third-party code with full network access and, often, a writable checkout. That is a large blast radius. `penten` shrinks it:

- **Default-deny networking** — the container starts with zero outbound reach. You open exactly the host ports you need and nothing else.
- **No secret exposure to the workload** — the `github-token` is used only on the host to file the issue; it is never passed into the container.
- **Hardened by default** — unprivileged user, all Linux capabilities dropped, no privilege escalation, read-only root filesystem, memory/CPU/PID/FD limits, read-only project mount.
- **Results captured automatically** — the output command's stdout/stderr becomes a GitHub issue, safely fenced so output can't inject markdown.

## Quick start

Add the action to a workflow. This runs a command in an `alpine` container that is allowed to reach the host on port `5432` only, then files an issue with the result:

```yaml
permissions:
  contents: read
  issues: write

jobs:
  scan:
    runs-on: ubuntu-latest   # Linux runner with `sudo iptables` required
    steps:
      - uses: actions/checkout@v4
      - uses: BizSimple/penten@main
        with:
          image: alpine:3.20
          command: "ls -la /workspace && echo prepared"
          project-dir: .
          output-command: "nc -zv host.local 5432 || echo 'db not reachable'"
          host-ports: "5432"
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

The host is reachable from inside the container as **`host.local`** (also exported as `$HOST_IP`). Leave `host-ports` empty (the default) for a container with **no network access at all**.

A runnable end-to-end example that spins up a Postgres service and lets the container talk to it lives in [`.github/workflows/example.yml`](.github/workflows/example.yml).

## Inputs

| Input            | Required | Default       | Description |
|------------------|:--------:|---------------|-------------|
| `image`          | ✅       | —             | Docker image name (e.g. `alpine:3.20`, `node:22-slim`). |
| `command`        | ✅       | —             | Command run inside the container (via `/bin/sh -c`). |
| `project-dir`    | ✅       | —             | Shared project directory, mounted at `/workspace`. Relative paths resolve against the calling workflow's workspace and must stay inside `$GITHUB_WORKSPACE`. |
| `output-command` | ✅       | —             | Command run after `command`; its combined output is posted as an issue. |
| `github-token`   | ✅       | —             | Token with `issues: write`, used on the host to create the issue. |
| `host-ports`     | ❌       | `""`          | Comma-separated host TCP ports the container may reach (e.g. `"5432,8080"`). Empty = no network. |
| `run-as-user`    | ❌       | `1000:1000`   | UID or UID:GID the command runs as. Use `0:0` only if you truly need root inside. |
| `project-write`  | ❌       | `false`       | Mount `/workspace` writable. |
| `read-only-root` | ❌       | `true`        | Read-only container root filesystem with a tmpfs `/tmp`. |
| `memory`         | ❌       | `2g`          | Hard memory limit (e.g. `512m`, `2g`). |
| `cpus`           | ❌       | `2`           | CPU quota (e.g. `1`, `1.5`). |
| `issue-title`    | ❌       | auto          | Title for the created issue. Defaults to a workflow/run label. |

## Outputs

| Output         | Description                     |
|----------------|---------------------------------|
| `issue-url`    | URL of the created issue.       |
| `issue-number` | Number of the created issue.    |
| `exit-code`    | Exit code of the main command.  |

## How the sandbox works

At a glance, each run:

1. Creates a **dedicated bridge network** (Docker-allocated subnet, so concurrent jobs never collide) with inter-container communication disabled.
2. Installs `iptables` rules that **drop all forwarded egress** from that subnet and **default-deny** host-bound traffic, then opens one `ACCEPT` per allowed port. Rules are tagged with the network name and removed on cleanup — even if earlier steps fail.
3. Runs your `command`, then your `output-command`, under a hardened `docker run` (unprivileged user, `--cap-drop ALL`, `--security-opt no-new-privileges`, read-only root, resource limits, private namespaces).
4. Posts the output-command result as a **GitHub issue** and exposes `issue-url` / `issue-number` / `exit-code` as outputs.

For the full security model — DNS black-holing, capability dropping, path-confinement of `project-dir`, injection-safe issue rendering, and self-hosted-runner guidance — see the reference doc:

📖 **[docs/restricted-container-action.md](docs/restricted-container-action.md)**

## Requirements

- A **Linux runner** with `sudo iptables` available (e.g. `ubuntu-latest`). The action edits the host `INPUT` and `DOCKER-USER` chains and needs Docker.
- Workflow permissions: `issues: write` (to file the issue) and typically `contents: read`.

## Security notes

- The **output command's output is posted to a GitHub issue** visible to anyone who can see the repo. Don't print secrets in it.
- On **self-hosted runners**, prefer ephemeral runners (the action edits host firewall rules), never mount the Docker socket, keep `project-write` off unless required, and **pin images by digest** (`alpine:3.20@sha256:…`) for untrusted use.

See the [reference doc](docs/restricted-container-action.md#operational-guidance-for-self-hosted-runners) for details.

## Repository layout

| Path | Purpose |
|------|---------|
| [`action.yml`](action.yml) | The composite action definition (all logic lives here). |
| [`docs/restricted-container-action.md`](docs/restricted-container-action.md) | Full inputs/outputs reference and security model. |
| [`.github/workflows/example.yml`](.github/workflows/example.yml) | Runnable `workflow_dispatch` example with a Postgres service. |

## Contributing

Issues and pull requests are welcome. When changing the action:

- Keep the sandbox **default-deny** — new inputs should tighten, not loosen, the defaults.
- Any input expanded into the `docker run` command line must be **strictly validated** (see the `Set up restricted network` step in [`action.yml`](action.yml)).
- Update [`docs/restricted-container-action.md`](docs/restricted-container-action.md) and this README when inputs, outputs, or behavior change.
- Test against the example workflow before opening a PR.

## License

See the repository for license details.
