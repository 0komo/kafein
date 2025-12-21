{ ... }: {
  programs.erlfmt.enable = true;
  settings.programs.erlfmt.excludes = [
    "build/"
    "_build/"
  ];
  
  programs.gleam.enable = true;
}
