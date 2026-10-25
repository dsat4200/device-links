# Protocol and state

1. KDE Connect supplies LAN discovery, TLS identity and explicit pairing.
2. Both GUIs require human comparison of the timestamp-bound verification code.
3. Local approval records the remote certificate information independently of
   KDE Connect's paired flag. A paired flag alone never installs an SSH key.
4. `org.amber.devicelinks.identity` carries one JSON document, limited to 32 KiB:
   schema=1, hostname, user, sshPort, publicKey, hostKey, desktopEndpoints.
5. The receiver accepts only roster names, valid usernames/ports, structurally
   valid Ed25519 keys and RDP/VNC endpoint declarations. The hostname remains
   only a label; the approved certificate is the identity. Conflicting names,
   changed SSH keys and changed certificates fail closed and need reapproval.
   The descriptor hostname must match the name shown in the approval dialog.
6. Public keys enter the separate app-owned AuthorizedKeysFile declared by Nix.
   There are no edits to manual authorized_keys and no root pairing service.
7. SSH clients require a pinned host key; forwarding and agent forwarding are
   disabled. Remmina receives only the verified host's normal .local endpoint.

App data: `$DEVICE_LINKS_STATE`, default `~/.local/share/device-links` (0700).
It contains peers.json and app-owned authorized_keys / known_hosts (0600).
The Secret Service stores the persistent private identity; the unlocked runtime
copy lives in `$XDG_RUNTIME_DIR/device-links/identity` (0600). No /tmp fallback.
Remmina profiles are writable and app-prefixed. Only owned connection fields
are merged, preserving other fields. An owned marker block in normal
~/.ssh/known_hosts supports Remmina; all other content is preserved.

Local IPC: mode-0600 Unix socket below that runtime directory, one JSON request
per connection. Supported operations: show, list, scan, doctor, resolve, gsudo.
Pair/approve/accept are deliberately not in the agent API. gsudo streams bounded
base64 stdout/stderr frames and a final exit code. Same-UID local applications
can request a prompt but not approve it through this API.

Readiness (0.1.1): do not use QDBusInterface.isValid() for a live object: Qt may
return true while Introspect/actual calls return UnknownObject. Explicit method
calls and Properties.Get avoid cached introspection. A successful paired flag
is followed by checking loadedPlugins, then publishing/receiving metadata.
UnknownObject/UnknownInterface/UnknownMethod or a disconnected service during
that handoff are retryable; no keys are installed without local approval and
validated metadata. Missing peer objects preserve existing grants, while an
explicitly observed unpaired state removes app-managed grants. Individual peer
errors never abort the entire scan. Polling is guarded against reentrancy, and
an active verification dialog cannot install keys or lose its pending state.
Approval rechecks the exact code, certificate and hostname after the human
responds, rejecting expired or changed requests rather than silently approving
a replacement. Session diagnostics expose only bounded operation/error metadata.

Remote sudo worker: launched only through authenticated, host-key-pinned SSH
using the stable system paths (`/run/current-system/sw/bin/device-links` and the
setuid `/run/wrappers/bin/sudo`), because sshd's non-interactive PATH excludes
user profiles. It validates a password with `sudo -S -v` in a pipe, then
executes argv with `sudo -n --` and closed stdin. This keeps the password out of
the command's stdin, argv, environment and logs. The persistent worker is the
parent of all sudo calls on that connection, providing the no-TTY parent-PID
ticket scope. No global sudoers change is installed. Ticket behavior must be
tested on the target's sudo/PAM policy: a policy with terminal/global tickets may
share one with other no-terminal processes of the same user, and unsupported
policies may prompt more often, never fall back to passwordless access. Without
Remember, invalidate after each command. EOF, cancellation or backend shutdown
ends the worker and its ticket.

Limitations: discovery is same-LAN, pairing needs a graphical session, desktop
endpoint declarations do not install/enable a server, and revocation cannot
terminate independently established sessions or undo a compromised account.
