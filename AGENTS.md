# Device Links

Read README.md and docs/PROTOCOL.md before changing authentication or pairing.
This is the application repository. NixOS integration lives in ~/nixos-config.
Never commit credentials, device keys, pairing databases or Remmina profiles.
Use `nix build` and `nix flake check`; tests must use isolated HOME/XDG directories.
Never pair real devices, change live authorized keys or activate NixOS to test code.
Discovery is untrusted. Only explicit human-approved, certificate-bound peers may
install keys. All commands use OpenSSH, never the discovery transport.
