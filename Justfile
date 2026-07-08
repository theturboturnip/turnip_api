set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
set dotenv-load := true

default:
    @just --list

serve:
    cargo run

test:
    cargo test

# would require debian docker.io, docker-cli, docker-buildx - but I'm on debian 12 rn.
docker-build:
    sudo docker build -t turnip_server .


#- /etc/timezone:/etc/timezone:ro
#- /usr/share/zoneinfo:/usr/share/zoneinfo:ro

docker-run:
    sudo docker run -d -p 3000:3000 --mount type=bind,src=/etc/timezone,dst=/etc/timezone,ro --mount type=bind,src=/usr/share/zoneinfo,dst=/usr/share/zoneinfo,ro  --env-file ./.env turnip_server
