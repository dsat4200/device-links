# Device Links

A small GUI for explicitly approved LAN SSH links between configured NixOS
devices. Remmina remains the remote desktop client: Device Links maintains its
connection profiles, not a desktop viewer or a desktop streaming server.

## Use

After the NixOS integration is installed on both devices, open **Device Links**.
Nearby configured peers appear automatically. **Rescan** refreshes discovery.
Click **Link**, compare the verification code on both screens, and approve on
both devices. This grants ordinary SSH access to the `amber` account in both
directions. Pairing itself does not require sudo or an SSH password login.

Use **Open in Remmina**, **Open SSH**, or the two test buttons. Desktop entries
are created only for RDP/VNC endpoints reported by the peer's configuration;
an SSH entry is always created after linking. Desktop passwords belong to
Remmina and its normal credential dialog/keyring. No desktop server is enabled.

The window opens once at graphical login. Closing it leaves discovery running.
The application identity is encrypted at rest in the login Secret Service
keyring; its working private key exists only in the mode-0700 user runtime
directory. No private keys, passwords or pairing state belong in either repo.
Linked SSH still works when the target's window is closed; a first pairing
needs both peers' graphical session backends running.

## Agents and troubleshooting

```sh
device-links --help
device-links list --json
device-links scan --json
device-links doctor desktop --json
device-links exec desktop -- hostname
device-links gsudo desktop "Check SSH service" -- systemctl status sshd
journalctl --user -u device-links.service
```

`doctor` reports backend status, last SSH checks, identity/discovery problems,
and separately reported desktop capabilities. **Test SSH** or **Rescan** repeats
checks. Reports exclude private keys/passwords and command output. Discovery
names are untrusted; a roster match is not authentication. Never disable SSH
host-key checking, enable SSH password login, or weaken VPN policy to repair a
pair. Wi-Fi client isolation, multicast filtering and VPN LAN restrictions can
prevent discovery or SSH; the app cannot override those network policies.

Remote administrator commands use a dedicated SSH worker and a local password
dialog. They are noninteractive: their stdin is closed; use `exec` or an SSH
terminal for interactive programs. The dialog identifies the target, purpose
and exact argv. Cancellation does not execute the command. “Remember” reuses
the target's sudo ticket for that no-terminal SSH session, subject to sudo/PAM
expiry and a five-minute connection idle limit. No password is cached or
persisted. Sudo policy may share that ticket with another no-terminal process
of the same target user while the link is open; disconnecting invalidates it.
Closing the window does not end remembered authorization; stopping the backend
or logging out does. Screen locking is not currently a logout; use **Unlink** or
stop the backend to end an active link session immediately.

Unlink removes app-managed keys, host entries and profiles, not independently
configured access or already-running SSH sessions. A compromised peer can have
made other account changes while trusted: unlink is not compromise recovery.

## Source and integration

Application: this repository. System policy: `~/nixos-config`.
The config pins an application commit; `amber pull` prefetches that locked
public source and `rebuild` installs the matching version. No GitHub sign-in is
required to fetch it. No moving-branch updater runs in the app or as root.

The dedicated KDE Connect build includes only the identity-exchange plugin.
It exchanges bounded public metadata, never commands or passwords. OpenSSH
does all command execution. Local same-user IPC exposes no pairing-approval
operation: a human uses the GUI. Same-user applications already share the
account's authority; this is not a sandbox against malicious local processes.

See [protocol and state](docs/PROTOCOL.md). Build with `nix build`; run tests with
`nix flake check`. Do not test by changing a real user's SSH trust database.

Version 0.1 is an initial implementation. Automated tests do not substitute for
two-device acceptance testing of discovery, keyring unlock, sudo ticket scope,
and the actual Remmina/libssh plugins.
