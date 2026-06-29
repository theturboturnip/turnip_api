set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
set dotenv-load := true

default:
    @just --list

serve:
    cargo run

test:
    cargo test
