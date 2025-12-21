{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flakelight.url = "github:nix-community/flakelight";
    flakelight-treefmt.url = "github:m15a/flakelight-treefmt";

    flakelight.inputs.nixpkgs.follows = "nixpkgs";
    flakelight-treefmt.inputs.flakelight.follows = "flakelight";
  };

  outputs = { flakelight, ... }@inputs:
    flakelight ./.
    {
      inherit inputs;

      imports = with inputs; [
        flakelight-treefmt.flakelightModules.default
      ];
      
      devShell.packages = pkgs: with pkgs; [
        gleam
        deno
        erlang-language-platform
      ] ++ (with beam28Packages; [
        erlang
        rebar3
      ]);

      treefmtConfig = import ./treefmt.nix;
    };
}
