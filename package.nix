{ pkgs }:
let
  kdeconnect = pkgs.kdePackages.kdeconnect-kde.overrideAttrs (old: {
    postPatch = (old.postPatch or "") + ''
      cp -r ${./plugin} plugins/devicelinks
      chmod -R u+w plugins/devicelinks
      # This dedicated build has no clipboard, input or other unrelated plugins.
      echo 'add_subdirectory(devicelinks)' > plugins/CMakeLists.txt
      # Keep only headless discovery/pairing core, the LAN daemon and the
      # identity plugin. The desktop app, SMS, CLI, plasmoid and KIO bridges
      # are unrelated to Device Links and dominate compile time and closure.
      for component in app cli indicator urlhandler smsapp plasmoid kio \
          nautilus-extension fileitemactionplugin declarativeplugin; do
        substituteInPlace CMakeLists.txt --replace-fail "add_subdirectory(''${component})" ""
      done
    '';
    cmakeFlags = (old.cmakeFlags or [ ]) ++ [ "-DBUILD_TESTING=OFF" ];
    postInstall = (old.postInstall or "") + ''
      # Device Links owns startup and the approval UI, not KDE Connect's applets.
      rm -f $out/etc/xdg/autostart/*.desktop
    '';
  });
  python = pkgs.python3.withPackages (ps: [ ps.pyside6 ps.keyring ps.secretstorage ]);
in pkgs.stdenvNoCC.mkDerivation {
  pname = "device-links";
  version = "0.1.0";
  src = pkgs.lib.cleanSource ./.;
  nativeBuildInputs = [ pkgs.makeWrapper pkgs.qt6.wrapQtAppsHook ];
  nativeCheckInputs = [ pkgs.openssh ];
  buildInputs = [ pkgs.qt6.qtbase ];
  dontWrapQtApps = true;
  dontBuild = true;
  doCheck = true;
  checkPhase = ''
    export PYTHONDONTWRITEBYTECODE=1 QT_QPA_PLATFORM=offscreen
    ${python}/bin/python -m unittest discover -s tests -v
  '';
  installPhase = ''
    mkdir -p $out/lib/device-links $out/bin $out/share/doc/device-links
    cp -r device_links $out/lib/device-links/
    find $out/lib/device-links -type d -name __pycache__ -prune -exec rm -rf {} +
    cp README.md docs/PROTOCOL.md $out/share/doc/device-links/
    makeWrapper ${python}/bin/python $out/bin/device-links \
      --add-flags "-m device_links" \
      --prefix PYTHONPATH : $out/lib/device-links \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.remmina pkgs.kitty pkgs.systemd ]} \
      --set DEVICE_LINKS_KDECONNECT ${kdeconnect}/bin/kdeconnectd \
      "''${qtWrapperArgs[@]}"
  '';
  passthru = { inherit kdeconnect python; };
  meta = { description = "Approved LAN SSH links and automatic Remmina profiles"; mainProgram = "device-links"; platforms = [ "x86_64-linux" ]; };
}
