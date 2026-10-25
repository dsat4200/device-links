{
  description = "Device Links: approved LAN SSH pairing and Remmina setup";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
    app = pkgs.callPackage ./package.nix { };
  in {
    packages.${system} = { default = app; device-links = app; };
    checks.${system}.device-links = app;
  };
}
