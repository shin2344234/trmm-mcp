# Client setup

Claude Code, Claude Desktop and LM Studio, each on macOS, Windows and Linux —
plus running the server over SSH with nothing listening on the network, and how
to install the TLS certificate so no client has to skip verification.

## Connecting a client

Claude Code, Claude Desktop and LM Studio are covered below, each on macOS,
Windows and Linux. Whichever you use, you need two things from the server: the
**bearer token** from `.env`, and a copy of **`certs/cert.pem`** so the client
can verify the TLS certificate.

Copy the certificate over first.

macOS and Linux:

```bash
scp rmmuser@192.0.2.10:/opt/trmm-mcp/certs/cert.pem ~/trmm-mcp-cert.pem
```

Windows (PowerShell):

```powershell
scp rmmuser@192.0.2.10:/opt/trmm-mcp/certs/cert.pem $env:USERPROFILE\trmm-mcp-cert.pem
```

### Claude Code — macOS, Windows, Linux

The simplest of the three, because Claude Code speaks HTTP directly and needs no
bridge:

```bash
claude mcp add --transport http trmm https://192.0.2.10:8770/mcp \
  --header "Authorization: Bearer <TRMM_MCP_AUTH_TOKEN>" --scope user
```

`--scope user` makes it available across all your projects; leave it off for the
current project only. Claude Code reads the operating system's certificate
store, so once you have installed the certificate (see
[Trusting the certificate](#trusting-the-certificate)) nothing further is
needed.

On the server itself you can skip the network entirely and run it over stdio:

```bash
claude mcp add trmm -- /opt/trmm-mcp/run.sh readonly
```

Swap `readonly` for `elevate` to get the approval gate, or `command` for
unattended execution. Keeping two entries (`trmm` and `trmm-command`) makes the
active capability obvious at a glance.

### Claude Desktop — macOS, Windows, Linux (beta)

Desktop's built-in "custom connector" UI cannot reach this server. Those
connectors are dialled from Anthropic's own infrastructure, so a private address
is unroutable from there and a self-signed certificate is rejected.
`claude_desktop_config.json` is stdio-only as well — it has no `url` field. The
working route is `mcp-remote`, a small Node bridge that Desktop launches locally
and which speaks HTTP to this server. Node 18+ is required.

Open the config with **Settings → Developer → Edit Config** (the Claude menu in
the menu bar or app menu, not the in-window account settings). That button opens
whichever file the install actually reads, which saves you guessing. The paths,
if you want them directly:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` (not documented by Anthropic; prefer the in-app button) |

**macOS and Linux** — `npx` is invoked directly:

```json
{
  "mcpServers": {
    "tacticalrmm": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote@latest",
        "https://192.0.2.10:8770/mcp",
        "--transport", "http-only",
        "--header", "Authorization:${AUTH_HEADER}"
      ],
      "env": {
        "AUTH_HEADER": "Bearer <TRMM_MCP_AUTH_TOKEN from .env>",
        "NODE_EXTRA_CA_CERTS": "/Users/you/trmm-mcp-cert.pem"
      }
    }
  }
}
```

On Linux the certificate path is typically `/home/you/trmm-mcp-cert.pem`.

**Windows** — the same thing wrapped in `cmd /c`:

```json
{
  "mcpServers": {
    "tacticalrmm": {
      "command": "cmd",
      "args": [
        "/c", "npx", "-y", "mcp-remote@latest",
        "https://192.0.2.10:8770/mcp",
        "--transport", "http-only",
        "--header", "Authorization:${AUTH_HEADER}"
      ],
      "env": {
        "AUTH_HEADER": "Bearer <TRMM_MCP_AUTH_TOKEN from .env>",
        "NODE_EXTRA_CA_CERTS": "C:\\Users\\YOU\\trmm-mcp-cert.pem"
      }
    }
  }
}
```

Three details worth understanding:

- `cmd /c` is a Windows-only workaround. There, `npx` is the batch shim
  `npx.cmd`, which Node only resolves through `PATHEXT` when spawned with a
  shell; Electron hosts that spawn without one fail with `spawn npx ENOENT`. No
  such shim exists on macOS or Linux, so the wrapper is unnecessary there. Some
  Windows builds do spawn with a shell and work without it — treat `cmd /c` as
  the safe default rather than a hard requirement.
- `Authorization:${AUTH_HEADER}` with the value in `env`, and no space after the
  colon. Claude Desktop on Windows does not escape spaces inside `args`, which
  splits a literal `Bearer xyz` into stray arguments. mcp-remote expands
  `${VAR}` itself, so the space stays safely inside the variable. Harmless on
  every platform, so use it everywhere.
- `NODE_EXTRA_CA_CERTS` is the same variable name on all three systems. It
  *appends* to Node's trust store rather than disabling verification, so the
  certificate still has to match the address you dial. Prefer it over
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, which switches verification off for
  everything that process touches. Escape the backslashes on Windows.

Then quit Claude Desktop completely and reopen it. On Windows and macOS, closing
the window leaves it running — use the tray or menu-bar icon and pick Quit.
Start a new chat afterwards, since the tool list is fixed when a conversation
begins.

If Desktop appears to ignore your config on Windows, you are probably on the
MSIX build from the Store or WinGet, which virtualizes the filesystem. It reads
`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\`, while the "Edit
Config" button may open the un-virtualized `%APPDATA%` copy. Find the real one:

```powershell
$p = Get-ChildItem "$env:LOCALAPPDATA\Packages\Claude_*" -Directory | Select-Object -First 1
"$($p.FullName)\LocalCache\Roaming\Claude\claude_desktop_config.json"
```

To test the bridge outside Desktop when something misbehaves:

```bash
npx -p mcp-remote@latest mcp-remote-client https://192.0.2.10:8770/mcp --transport http-only --header "Authorization: Bearer <token>"
```

Connection failures are logged to `mcp.log`, and each server's stderr to
`mcp-server-tacticalrmm.log` — under `~/Library/Logs/Claude` on macOS and
`%APPDATA%\Claude\logs` on Windows (with the same MSIX redirect).

### LM Studio — macOS, Windows, Linux

LM Studio speaks remote HTTP natively, so no bridge is needed. Edit `mcp.json`
through the app: right sidebar → **Program** → **Install** → **Edit mcp.json**.
The documented path (`~/.lmstudio/mcp.json`) and the path several versions
actually use (`~/.cache/lm-studio/mcp.json`) disagree, so the in-app editor is
the reliable route.

```json
{
  "mcpServers": {
    "tacticalrmm": {
      "url": "https://192.0.2.10:8770/mcp",
      "headers": { "Authorization": "Bearer <TRMM_MCP_AUTH_TOKEN from .env>" },
      "timeout": 60000
    }
  }
}
```

Two caveats. LM Studio rejects self-signed certificates and offers no setting to
trust one, so start it with the CA in the environment:

```bash
NODE_EXTRA_CA_CERTS=~/trmm-mcp-cert.pem "/Applications/LM Studio.app/Contents/MacOS/LM Studio"   # macOS
NODE_EXTRA_CA_CERTS=~/trmm-mcp-cert.pem lm-studio                                                # Linux
```

```powershell
$env:NODE_EXTRA_CA_CERTS="$env:USERPROFILE\trmm-mcp-cert.pem"; & "$env:LOCALAPPDATA\Programs\LM Studio\LM Studio.exe"
```

And recent versions block private IP addresses for servers added dynamically
through the API. Declaring the server in `mcp.json`, as above, is the supported
way around that.

LM Studio prompts before every tool call and shows the arguments, which is a
useful second pair of eyes — but it is the client asking, and it can be set to
"always allow". The approval gate on this server is the real boundary.

### Over SSH instead — no open port

Rather than exposing the HTTP listener, a client can run the stdio server across
SSH. Nothing listens on the network and SSH keys do the authentication. This
suits Claude Desktop, which has no HTTP transport of its own.

Confirm passwordless SSH from the workstation first.

macOS and Linux:

```bash
ssh -o BatchMode=yes rmmuser@192.0.2.10 "echo OK"
ssh-keygen -t ed25519 -C "mcp-client"                      # if it prompted
ssh-copy-id rmmuser@192.0.2.10
```

Windows (PowerShell):

```powershell
ssh -o BatchMode=yes rmmuser@192.0.2.10 "echo OK"
ssh-keygen -t ed25519 -C "mcp-client"                      # if it prompted
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh rmmuser@192.0.2.10 "cat >> ~/.ssh/authorized_keys"
```

Then, in `claude_desktop_config.json` — `ssh` on macOS and Linux,
`C:\\Windows\\System32\\OpenSSH\\ssh.exe` on Windows:

```json
{
  "mcpServers": {
    "tacticalrmm": {
      "command": "ssh",
      "args": [
        "-T",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "rmmuser@192.0.2.10",
        "/opt/trmm-mcp/run.sh readonly"
      ]
    }
  }
}
```

`-T` is required: a pseudo-TTY would corrupt the JSON-RPC stream. `BatchMode`
makes a missing key fail immediately instead of hanging on a password prompt the
client cannot answer.

Verified on this server: launching under a minimal environment from a different
working directory still handshakes cleanly, and `~/.bashrc` has the standard
non-interactive guard, so nothing pollutes the protocol stream.

### Trusting the certificate

Node-based clients (Claude Desktop via mcp-remote, LM Studio) read
`NODE_EXTRA_CA_CERTS` and need nothing else. Claude Code and your browser read
the operating system store, so install the certificate there to use the approval
page without warnings.

**macOS:**

```bash
sudo security add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain ~/trmm-mcp-cert.pem
```

**Windows** (elevated prompt):

```cmd
certutil -addstore -f root "%USERPROFILE%\trmm-mcp-cert.pem"
```

**Linux** (Debian/Ubuntu — note the `.crt` extension is required):

```bash
sudo cp ~/trmm-mcp-cert.pem /usr/local/share/ca-certificates/trmm-mcp.crt && sudo update-ca-certificates
```

**Linux** (RHEL/Fedora):

```bash
sudo cp ~/trmm-mcp-cert.pem /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust extract
```

Two browser quirks. Firefox keeps its own certificate store on every platform
and ignores the system one, so import there separately or set
`security.enterprise_roots.enabled` in `about:config`. Chrome on Linux also uses
its own NSS database rather than the system bundle:

```bash
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "trmm-mcp" -i ~/trmm-mcp-cert.pem
```

Alternatively just accept the browser warning once — the approval page still
protects itself with a password and TOTP.

