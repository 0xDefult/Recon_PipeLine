#!/bin/bash
#####################################################################
# ETHICAL HACKING TOOL - AUTHORIZED TARGETS ONLY
# Technology Fingerprinting Script
# Usage: ./tech-fingerprint.sh <domain>
# Rate Limited: Max 10 req/sec to prevent DoS
#####################################################################

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_DIR="$(dirname "$SCRIPT_DIR")"
export PATH="$PATH:$(go env GOPATH)/bin"
USER_AGENT="ReconPipeline/1.0 (Ethical Recon; +https://example.com)"

# Sensitive technologies to flag
SENSITIVE_TECHS="jenkins|phpmyadmin|grafana|admin|dashboard|login|wp-admin|phpinfo|config|.git|.env|backup"

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
    local tech_file="$data_dir/tech/${today}.txt"
    local sensitive_file="$data_dir/tech/sensitive-${today}.txt"

    mkdir -p "$data_dir/tech"

    log "Starting technology fingerprinting for $domain"

    # Get live hosts from today
    if [[ ! -f "$live_file" ]]; then
        warn "No live hosts file found - running subdomain scan first"
        "$SCRIPT_DIR/subdomain-monitor.sh" "$domain"
    fi

    if [[ ! -s "$live_file" ]]; then
        error "No live hosts to fingerprint"
        exit 0
    fi

    local host_count=$(wc -l < "$live_file")
    log "Fingerprinting $host_count live hosts"

    # Run httpx with technology detection
    cat "$live_file" | httpx -tech-detect -title -status-code -silent 2>/dev/null > "$tech_file" || true

    local tech_count=$(wc -l < "$tech_file")
    log "Technology detection complete: $tech_count results"

    # Flag sensitive technologies
    grep -iE "$SENSITIVE_TECHS" "$tech_file" > "$sensitive_file" 2>/dev/null || true

    if [[ -s "$sensitive_file" ]]; then
        local sensitive_count=$(wc -l < "$sensitive_file")
        log "FOUND $sensitive_count sensitive technologies!"

        local alert_file="$PIPELINE_DIR/alerts/sensitive-tech-${today}.txt"
        cp "$sensitive_file" "$alert_file"
        log "Sensitive tech saved to $alert_file"

        # Notify
        if command -v notify &>/dev/null && [[ -f "$PIPELINE_DIR/config/notify-config.yaml" ]]; then
            notify -bulk -data "$alert_file" -config "$PIPELINE_DIR/config/notify-config.yaml" 2>/dev/null || true
        fi
    fi

    log "Technology fingerprinting complete"
    log "Results: $tech_file"
}

main "$@"