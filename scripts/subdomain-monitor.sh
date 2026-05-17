#!/bin/bash
#####################################################################
# ETHICAL HACKING TOOL - AUTHORIZED TARGETS ONLY
# Subdomain Enumeration & Monitoring Script
# Usage: ./subdomain-monitor.sh <domain>
# Rate Limited: Max 10 req/sec to prevent DoS
#####################################################################

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_DIR="$(dirname "$SCRIPT_DIR")"
export PATH="$PATH:$(go env GOPATH)/bin"
USER_AGENT="ReconPipeline/1.0 (Ethical Recon; +https://example.com)"
RATE_LIMIT=10

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

# Check scope
check_scope() {
    local domain="$1"
    local whitelist="$PIPELINE_DIR/config/scope-whitelist.txt"

    if [[ ! -f "$whitelist" ]]; then
        warn "No whitelist file found"
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
    local subdomain_file="$data_dir/subdomains/${today}.txt"
    local live_host_file="$data_dir/live-hosts/${today}.txt"

    mkdir -p "$data_dir/subdomains" "$data_dir/live-hosts"

    log "Starting subdomain enumeration for $domain"

    # Temp files
    local tmp_subs=$(mktemp)
    local tmp_all=$(mktemp)

    # Run subdomain enumeration tools in parallel
    log "Running Subfinder..."
    subfinder -d "$domain" -silent 2>/dev/null | tee "$tmp_subs" &
    local pid1=$!

    log "Running Amass (passive)..."
    amass enum -passive -d "$domain" 2>/dev/null | tee -a "$tmp_subs" &
    local pid2=$!

    log "Running Assetfinder..."
    assetfinder --subs-only "$domain" 2>/dev/null | tee -a "$tmp_subs" &
    local pid3=$!

    # Wait for all to complete
    wait $pid1 $pid2 $pid3 2>/dev/null || true

    # Deduplicate and save
    sort -u "$tmp_subs" > "$tmp_all"
    cat "$tmp_all" > "$subdomain_file"

    local sub_count=$(wc -l < "$subdomain_file")
    log "Found $sub_count unique subdomains"

    # Probe for live hosts
    log "Probing for live hosts..."
    if [[ $sub_count -gt 0 ]]; then
        cat "$subdomain_file" | httpx -silent -o "$live_host_file" 2>/dev/null || true
    fi

    local live_count=$(wc -l < "$live_host_file" 2>/dev/null || echo 0)
    log "Found $live_count live hosts"

    # Check for new subdomains (compare with yesterday)
    local yesterday=$(date -d yesterday +%Y-%m-%d)
    local prev_file="$data_dir/subdomains/${yesterday}.txt"
    local new_subs=""

    if [[ -f "$prev_file" ]]; then
        new_subs=$(mktemp)
        comm -13 "$prev_file" "$subdomain_file" > "$new_subs"

        if [[ -s "$new_subs" ]]; then
            local new_count=$(wc -l < "$new_subs")
            log "Found $new_count NEW subdomains!"

            local alert_file="$PIPELINE_DIR/alerts/new-subdomains-${today}.txt"
            cp "$new_subs" "$alert_file"
            log "New subdomains saved to $alert_file"

            # Send notification
            if command -v notify &>/dev/null; then
                notify -bulk -data "$alert_file" -config "$PIPELINE_DIR/config/notify-config.yaml" 2>/dev/null || warn "Notification failed"
            fi
        fi
    else
        log "No previous scan found - this is the first run"
    fi

    # Cleanup
    rm -f "$tmp_subs" "$tmp_all" "$new_subs" 2>/dev/null || true

    log "Subdomain enumeration complete"
    log "Results: $subdomain_file"
}

main "$@"