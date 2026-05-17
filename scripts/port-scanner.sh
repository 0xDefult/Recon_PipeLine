#!/bin/bash
#####################################################################
# ETHICAL HACKING TOOL - AUTHORIZED TARGETS ONLY
# Port Scanning Script
# Usage: ./port-scanner.sh <domain>
# Rate Limited: Max 10 req/sec to prevent DoS
#####################################################################

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_DIR="$(dirname "$SCRIPT_DIR")"
export PATH="$PATH:$(go env GOPATH)/bin"
USER_AGENT="ReconPipeline/1.0 (Ethical Recon; +https://example.com)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

check_scope() {
    local domain="$1"
    local whitelist="$PIPELINE_DIR/config/scope-whitelist.txt"

    if [[ ! -f "$whitelist" ]]; then
        return 0
    fi

    grep -q "^${domain}$" "$whitelist" 2>/dev/null || grep -q "^\*.${domain}$" "$whitelist" 2>/dev/null || {
        error "Domain $domain not in whitelist"
        exit 1
    }
}

main() {
    local domain="${1:-}"

    if [[ -z "$domain" ]]; then
        echo "Usage: $0 <domain>"
        exit 1
    fi

    check_scope "$domain"

    local today=$(date +%Y-%m-%d)
    local data_dir="$PIPELINE_DIR/data/$domain"
    local live_file="$data_dir/live-hosts/${today}.txt"
    local port_file="$data_dir/ports/${today}.txt"

    mkdir -p "$data_dir/ports"

    log "Starting port scanning for $domain"

    # Get live hosts
    if [[ ! -f "$live_file" ]]; then
        warn "No live hosts - running subdomain scan first"
        "$SCRIPT_DIR/subdomain-monitor.sh" "$domain"
    fi

    if [[ ! -s "$live_file" ]]; then
        error "No live hosts to scan"
        exit 0
    fi

    local host_count=$(wc -l < "$live_file")
    log "Scanning $host_count hosts (top 1000 ports)"

    # Fast scan with Naabu
    naabu -list "$live_file" -top-ports 1000 -silent 2>/dev/null > "$port_file" || true

    local port_count=$(wc -l < "$port_file")
    log "Port scan complete: $port_count open ports found"

    # Check for new ports (compare with yesterday)
    local yesterday=$(date -d yesterday +%Y-%m-%d)
    local prev_file="$data_dir/ports/${yesterday}.txt"

    if [[ -f "$prev_file" ]]; then
        local new_ports=$(comm -13 "$prev_file" "$port_file" 2>/dev/null || true)

        if [[ -n "$new_ports" ]]; then
            log "Found NEW open ports!"
            local alert_file="$PIPELINE_DIR/alerts/new-ports-${today}.txt"
            echo "$new_ports" > "$alert_file"

            if command -v notify &>/dev/null && [[ -f "$PIPELINE_DIR/config/notify-config.yaml" ]]; then
                notify -bulk -data "$alert_file" -config "$PIPELINE_DIR/config/notify-config.yaml" 2>/dev/null || true
            fi
        fi
    fi

    log "Port scanning complete"
    log "Results: $port_file"
}

main "$@"