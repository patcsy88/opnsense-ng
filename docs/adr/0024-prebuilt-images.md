# ADR-0024: Prebuilt container images from GitHub Actions

- Status: accepted (approved by project owner on 2026-11-17); the publishing workflow is untested until it first runs on GitHub
- Date: 2026-11-17
- Deciders: project owner

## Context

`install.sh` built the backend and frontend images on the target host. That needs about 3 GB of disk, Node and PyPI access, and a few minutes, and every update rebuilt them. The repository is public.

## Decision

- A GitHub Actions workflow (`.github/workflows/publish-images.yml`) builds `backend` and `frontend` on every push to `main` and publishes them to GHCR as `ghcr.io/patcsy88/opnsense-ng-backend` and `-frontend`, for `linux/amd64` and `linux/arm64`. Tags: `latest` and the commit SHA.
- `docker-compose.yml` names these images and keeps `build:`. `docker compose pull` fetches them, and `docker compose build` still builds locally.
- `install.sh` pulls by default. `INSTALL_BUILD=1` builds on the host instead.
- `APP_TAG` in `.env` pins a host to a commit SHA instead of `latest`.

## Consequences

- Hosts need no build toolchain and install in about a minute.
- The workflow uses only the built-in `GITHUB_TOKEN` and no stored secrets. It adds third-party actions (checkout, QEMU, buildx, login, build-push) from `actions/` and `docker/`.
- New GHCR packages are private by default. The owner must set each package to Public once (GitHub, Packages, Package settings), or the host pull fails.
- Images are not signed and there is no vulnerability scan yet. `latest` follows `main`, so a host that updates gets whatever was last pushed. Pin `APP_TAG` for control.
- Postgres and Caddy remain the official images, pulled as before.
