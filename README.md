# Hex-Rays IDA MCP

Official Hex-Rays IDA MCP Server, see the [announcement blog post](https://hex-rays.com/blog/hex-rays-ida-mcp-server) for more information.

## Installation

### Requirements

- Installed in your PATH
  - [Git](https://git-scm.com/)
  - [uv](https://github.com/astral-sh/uv)
- IDA 9.4 or higher with idalib and Python 3.11+
- We recommend disabling other IDA MCP servers to reduce agent confusion

### Automatic installation

Install the Hex-Rays IDA MCP using [hcli](https://hcli.docs.hex-rays.com/):

```bash
uvx ida-hcli mcp install
# or if you have hcli installed:
hcli mcp install
```

This will install the GUI plugin and interactively offer you to install the supported agent plugins.

### Manual installation

<details>

<summary>Manual installation instructions...</summary>

#### IDA GUI Plugin

To support IDA GUI instances when using IDA MCP, install the plugin:

```bash
uvx ida-hcli plugin install ida-mcp@https://github.com/HexRaysSA/ida-mcp
# or if you have hcli installed:
hcli plugin install ida-mcp@https://github.com/HexRaysSA/ida-mcp
```

_Note_: Without the GUI plugin, IDA MCP will still work headlessly.

#### [Claude Code](https://claude.com/product/claude-code)

```bash
# Add Hex-Rays marketplace
claude plugin marketplace add HexRaysSA/claude-marketplace
# Install plugin
claude plugin install ida-mcp@HexRaysSA
# Update to latest version
claude plugin update ida-mcp@HexRaysSA
```

#### [Codex CLI](https://learn.chatgpt.com/docs/codex/cli)

```bash
# Add Hex-Rays marketplace
codex plugin marketplace add HexRaysSA/codex-marketplace
# Install plugin
codex plugin add ida-mcp@HexRaysSA
```

#### [GitHub Copilot CLI](https://github.com/features/copilot/cli)

```bash
# Add Hex-Rays marketplace
copilot plugin marketplace add HexRaysSA/copilot-marketplace
# Install plugin
copilot plugin install ida-mcp@HexRaysSA
# Update to latest version
copilot plugin update ida-mcp
```

#### [Pi](https://pi.dev/)

```bash
# Install extension
pi install git:github.com/HexRaysSA/ida-mcp@latest
# Update to latest version
pi update --extensions
```

#### [oh-my-pi](https://github.com/can1357/oh-my-pi)

```bash
# Install extension
omp plugin install github:HexRaysSA/ida-mcp#latest
# Update to latest version
omp plugin upgrade
```

#### Other agents

Configure a regular stdio MCP server in your MCP JSON configuration:

```json
{
  "mcpServers": {
    "ida": {
      "command": "uvx",
      "args": [
        "--exclude-newer=1s",
        "ida-mcp",
        "stdio",
        "--agent=my-agent"
      ]
    }
  }
}
```

`uvx` resolves the latest stable `ida-mcp` release from PyPI, so this
configuration does not need to be updated for each release.

`--agent=my-agent` is a human-chosen label (like `claude-code`, `cursor`,
`my-custom-agent`, etc.) used to differentiate sessions in the dashboard.

</details>

## CLI

```bash
# MCP server over standard input/output
uvx ida-mcp stdio --agent=my-agent

# MCP server over Streamable HTTP
uvx ida-mcp http --host 127.0.0.1 --port 8737

# Inspect session log
uvx ida-mcp dashboard --open

# Export session logs for troubleshooting
uvx ida-mcp logs
```

## Usage

Start your agent harness and ask it something like:

> Reverse /path/to/sample.elf for me in IDA

To test the GUI integration, open something in IDA and ask your harness:

> What do I have open in the IDA GUI?

## Remote samples: HTTP upload, then MCP confirm

`open_database(path)` only opens a **server-local** path. IDA and idalib run on
the machine that hosts this MCP server.

**stdio** is unchanged: the agent is on the same machine, so it can pass a
local filesystem path to `open_database`. There is no HTTP upload in stdio
mode.

**Remote Streamable HTTP** agents cannot send file bytes through MCP tools.
They ask for an absolute upload URL, POST the sample with curl, then confirm:

1. `upload_info()` → absolute `url` (and `path`, usually `/uploads`)
2. Upload with curl (or any HTTP client) to that URL
3. `confirm_upload(upload_id)` with the JSON `upload_id` → `{path, size, sha256}`
4. `open_database(path)` with that server path

Agents and curl are not browsers: they have no same-origin policy, so they
cannot infer `POST /uploads` from having reached `/mcp`. After a reverse proxy
the process listen address (`0.0.0.0`, `127.0.0.1`) is also the wrong URL.
`upload_info` therefore returns an **absolute** URL, in order:

1. `IDA_MCP_WEBDAV_URL` if set (a WebDAV collection on another host; method is `PUT`)
2. `IDA_MCP_PUBLIC_URL` if set (origin only, no `/uploads`)
3. This MCP request's `X-Forwarded-Proto` / `X-Forwarded-Host` / `Forwarded` /
   `Host`, plus `X-Forwarded-Prefix` or the server `--path-prefix` when the
   request was under that prefix
4. The bind host only when it is a concrete address such as `127.0.0.1`

A reverse proxy must forward the public host and scheme (`Host` or
`X-Forwarded-Host`, and `X-Forwarded-Proto: https`). If it cannot, set
`IDA_MCP_PUBLIC_URL=https://ida.example.com`.

WebDAV on another machine is only a drop zone: IDA cannot open that path.
`confirm_upload(filename)` GETs **only** `{IDA_MCP_WEBDAV_URL}/{filename}`
into the local inbox. Arbitrary URLs from the agent are rejected.

```bash
# Ask the MCP server for the URL, then:
curl -fsS -H "Authorization: Bearer $IDA_MCP_TOKEN" \
  -F "file=@sample.elf" \
  http://127.0.0.1:8737/uploads

# Raw body instead of multipart
curl -fsS -H "Authorization: Bearer $IDA_MCP_TOKEN" \
  -H "X-Filename: sample.elf" \
  --data-binary @sample.elf \
  http://127.0.0.1:8737/uploads

# WebDAV on another host (IDA_MCP_WEBDAV_URL is the collection):
curl -fsS -u "$IDA_MCP_WEBDAV_USER:$IDA_MCP_WEBDAV_PASSWORD" \
  -T sample.elf \
  "$IDA_MCP_WEBDAV_URL/sample.elf"
# then confirm_upload("sample.elf")
```

The JSON response includes `upload_id`, `path`, `size`, and `sha256`. Humans can
stop there and call `open_database` with `path`. Agents should still call
`confirm_upload` so the path comes back through MCP. `list_uploads` lists the
inbox; `delete_upload` removes one object (refused while a database lease holds
it — `close_database` first).

`/uploads` shares the HTTP port with Streamable MCP (`/mcp`) and does not
replace it.

### Environment variables

| Variable | Meaning |
|---|---|
| `IDA_MCP_INBOX` | Inbox directory. Default: `<IDA_MCP_STATE_DIR>/inbox`, or `<IDAUSR>/mcp/inbox` when the state directory is unset. Created at startup with mode `0700`. |
| `IDA_MCP_UPLOAD_MAX_BYTES` | Maximum sample size in bytes. Default: `268435456` (256 MiB). |
| `IDA_MCP_TOKEN` | If set, Streamable HTTP MCP and `/uploads` require `Authorization: Bearer <token>`. Never logged or returned by tools. |
| `IDA_MCP_PUBLIC_URL` | Optional public origin advertised by `upload_info` when Host / `X-Forwarded-*` would be wrong. Example: `https://ida.example.com`. |
| `IDA_MCP_WEBDAV_URL` | Optional WebDAV collection on another host. When set, `upload_info` advertises `PUT` here and `confirm_upload(filename)` downloads `{url}/{filename}` into the inbox. Example: `https://dav.example.com/ida-inbox`. |
| `IDA_MCP_WEBDAV_USER` | Basic-auth user for that collection. Never returned by tools. |
| `IDA_MCP_WEBDAV_PASSWORD` | Basic-auth password for that collection. Never returned by tools. |
| `IDA_MCP_STATE_DIR` | MCP state directory (sessions and, by default, the inbox). |

Binding HTTP to anything other than `127.0.0.1` or `::1` without `IDA_MCP_TOKEN`
fails at startup. stdio mode does not require the token.

```bash
IDA_MCP_TOKEN=... uvx ida-mcp http --host 0.0.0.0 --port 8737
uvx ida-mcp http --host 127.0.0.1 --port 8737
```

## Developers: IDA Nexus

The IDA MCP project is built on [IDA Nexus](https://github.com/HexRaysSA/ida-nexus),
which allows multiple clients to seamlessly share and operate on IDA databases.

You can build your own tools on top of the `ida-nexus` library, see
[the documentation](https://github.com/HexRaysSA/ida-nexus/blob/main/README.md#python-package-developers)
for more information.
