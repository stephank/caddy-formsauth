{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs";
  outputs = { self, nixpkgs }: {
    packages = nixpkgs.lib.mapAttrs (system: pkgs: {
      default = pkgs.caddy.overrideAttrs (old: {
        postPatch = (old.postPatch or "") + ''
          cp -r ${./.} formsauth
          chmod a+w formsauth
          rm formsauth/go.*
          awk '
            { print };
            /plug in Caddy modules here/ {
              print "\t_ \"github.com/caddyserver/caddy/v2/formsauth\""
            }
          ' < cmd/caddy/main.go > newmain.go
          mv newmain.go cmd/caddy/main.go
        '';
      });
    }) nixpkgs.legacyPackages;
  };
}
