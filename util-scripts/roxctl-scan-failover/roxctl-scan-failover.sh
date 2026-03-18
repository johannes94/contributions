#!/usr/bin/env bash
set -euo pipefail

# Required environment variables:
#   PRIMARY_CENTRAL         - Endpoint for the primary Central (e.g. central-primary.acs.rhcloud.com:443)
#   FAILOVER_CENTRAL        - Endpoint for the failover Central (e.g. central-failover.acs.rhcloud.com:443)
#   PRIMARY_ROX_API_TOKEN   - API token for the primary Central
#   FAILOVER_ROX_API_TOKEN  - API token for the failover Central
# Arguments:
#   $1                      - Full image reference to scan (e.g. quay.io/myorg/myimage:latest)
#   $@                      - Extra args passed to roxctl (e.g. --output json, --force)

: "${PRIMARY_CENTRAL:?PRIMARY_CENTRAL must be set}"
: "${FAILOVER_CENTRAL:?FAILOVER_CENTRAL must be set}"
: "${PRIMARY_ROX_API_TOKEN:?PRIMARY_ROX_API_TOKEN must be set}"
: "${FAILOVER_ROX_API_TOKEN:?FAILOVER_ROX_API_TOKEN must be set}"

IMAGE="${1:?Usage: $0 <image> [extra roxctl args...]}"
shift
EXTRA_ARGS=("$@")

is_available() {
    local endpoint="$1"
    local curl_out
    curl -sS -m5 --retry 3 --retry-all-errors "https://${endpoint}/v1/ping" > /dev/null
    return
}

scan_image() {
    local endpoint="$1"
    local token="$2"
    echo "Scanning image ${IMAGE} via ${endpoint}" >&2
    ROX_API_TOKEN="$token" roxctl -e "$endpoint" image scan --image "$IMAGE" "${EXTRA_ARGS[@]}"
}

if is_available "$PRIMARY_CENTRAL"; then
    scan_image "$PRIMARY_CENTRAL" "$PRIMARY_ROX_API_TOKEN"
elif is_available "$FAILOVER_CENTRAL"; then
    echo "Primary Central: ${PRIMARY_CENTRAL} is unavailable, falling back to failover: ${FAILOVER_CENTRAL}" >&2
    scan_image "$FAILOVER_CENTRAL" "$FAILOVER_ROX_API_TOKEN"
else
    echo "Both Primary Central (${PRIMARY_CENTRAL}) and Failover Central (${FAILOVER_CENTRAL}) are unavailable" >&2
    exit 1
fi
