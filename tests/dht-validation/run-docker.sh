#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
report=${DHT_REPORT_PATH:-"$repo_root/tests/dht-validation/DOCKER-TEST-REPORT.md"}
suite_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
image="vx6-dht-validation:local"
network="vx6-dht-validation-$suite_id"
container="vx6-dht-validation-$suite_id"
work=$(mktemp -d)

cleanup() {
	local status=${1:-$?}
	docker rm -f "$container" >/dev/null 2>&1 || true
	docker network rm "$network" >/dev/null 2>&1 || true
	rm -rf "$work"
	exit "$status"
}
trap cleanup EXIT

if ! docker info >/dev/null 2>&1; then
	printf 'Docker daemon unavailable; run with permission to use Docker.\n' >&2
	exit 2
fi
command -v go >/dev/null
command -v sha256sum >/dev/null
mkdir -p "$(dirname "$report")"

{
	printf '\n## DHT Docker Mesh Run %s\n\n' "$suite_id"
	printf -- '- Source HEAD: `%s`\n' "$(git -C "$repo_root" rev-parse HEAD)"
	if git -C "$repo_root" diff --quiet && git -C "$repo_root" diff --cached --quiet; then
		printf -- '- Working tree source changes: none\n'
	else
		printf -- '- Working tree source changes: present; this run includes them\n'
	fi
	printf -- '- Go: `%s`\n' "$(go version)"
	printf -- '- Docker: `%s`\n' "$(docker version --format '{{.Server.Version}}')"
	printf -- '- Host kernel: `%s`\n' "$(uname -r)"
	printf -- '- Topology: 3-, 5-, and 10-peer DHT meshes using IPv6 TCP listeners in an isolated Docker network\n'
	printf -- '- Scope: DHT protocol/lookup behavior; not IKE/IPsec or separate-container process isolation\n\n'
	printf 'Command: `bash tests/dht-validation/run-docker.sh`\n\n'
} >>"$report"

export GOCACHE=${GOCACHE:-/tmp/vx6-go-build}
export GOMODCACHE=${GOMODCACHE:-/tmp/vx6-go-mod}
if ! (cd "$repo_root" && CGO_ENABLED=0 go test -c -o "$work/dht-validation.test" ./tests/dht-validation) >"$work/build.log" 2>&1; then
	cat "$work/build.log" | tee -a "$report"
	printf '\n**Result: FAIL (test binary build failed).**\n' | tee -a "$report"
	exit 1
fi
cp "$(dirname "${BASH_SOURCE[0]}")/Dockerfile" "$work/Dockerfile"
{
	printf 'Test binary SHA-256: `%s`\n\n' "$(sha256sum "$work/dht-validation.test" | awk '{print $1}')"
	printf '```text\n'
	cat "$work/build.log"
	printf '```\n\n'
} >>"$report"

if ! docker build -t "$image" "$work" >"$work/docker-build.log" 2>&1; then
	cat "$work/docker-build.log" | tee -a "$report"
	printf '\n**Result: FAIL (Docker image build failed).**\n' | tee -a "$report"
	exit 1
fi
{
	printf 'Image ID: `%s`\n\n' "$(docker image inspect "$image" --format '{{.Id}}')"
	printf '```text\n'
	cat "$work/docker-build.log"
	printf '```\n\n### Test output\n\n```text\n'
} >>"$report"

docker network create --ipv6 --internal --subnet "fd42:6:71::/64" "$network" >/dev/null
set +e
docker run --rm --name "$container" --network "$network" --ip6 "fd42:6:71::10" \
	--cap-drop=ALL --security-opt=no-new-privileges "$image" 2>&1 | tee "$work/test.log" | tee -a "$report"
status=${PIPESTATUS[0]}
set -e
printf '```\n\n' >>"$report"
if ((status == 0)); then
	printf '**Result: PASS.** The containerized DHT IPv6 mesh scenarios passed.\n' | tee -a "$report"
else
	printf '**Result: FAIL (test exit %d).** See output above.\n' "$status" | tee -a "$report"
fi
exit "$status"
