{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = [
    pkgs.nodejs-18_x
    pkgs.lua5_1
  ];
}
