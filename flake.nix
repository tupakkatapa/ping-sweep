{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, treefmt-nix, ... }:
    let
      eachSystem = f: nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (system: f nixpkgs.legacyPackages.${system});
      treefmtFor = pkgs: treefmt-nix.lib.evalModule pkgs {
        projectRootFile = "flake.nix";
        programs = {
          nixpkgs-fmt.enable = true;
          deadnix.enable = true;
          statix.enable = true;
          rustfmt.enable = true;
        };
      };
    in
    {
      packages = eachSystem (pkgs: {
        ping-sweep = pkgs.callPackage ./package.nix { };
        default = self.packages.${pkgs.system}.ping-sweep;
      });

      devShells = eachSystem (pkgs: {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            rust-analyzer
            rustfmt
            clippy
            cargo
          ];
        };
      });

      formatter = eachSystem (pkgs:
        (treefmtFor pkgs).config.build.wrapper
      );
    };
}
