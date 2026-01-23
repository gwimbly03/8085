let
  pkgs = import <nixpkgs> {};
in
  pkgs.mkShell {
  packages = [
    pkgs.python314
    pkgs.python314Packages.pycryptodome
    pkgs.python314Packages.pillow

  ];

  env = {
    LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
      pkgs.stdenv.cc.cc
      pkgs.libxcrypt
    ];

    POETRY_VIRTUALENVS_IN_PROJECT = "true";
    POETRY_VIRTUALENVS_PATH = "{project-dir}/.venv";
    POETRY_VIRTUALENVS_PREFER_ACTIVE_PYTHON = "true";
  };
}

