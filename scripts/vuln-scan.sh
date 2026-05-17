#!/bin/bash
#####################################################################
# ETHICAL HACKING TOOL - AUTHORIZED TARGETS ONLY
# Vulnerability Scanning Script
# Usage: ./vuln-scan.sh <domain>
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
    local vuln_dir="$data_dir/vulns"

    mkdir -p "$vuln_dir"

    log "Starting vulnerability scanning for $domain"

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
    log "Scanning $host_count hosts for vulnerabilities"

    # Run Nuclei with severity filter
    local tmp_vulns=$(mktemp)
    cat "$live_file" | nuclei -severity medium,high,critical -silent 2>/dev/null > "$tmp_vulns" || true

    # Organize by severity
    local vuln_file="$vuln_dir/${today}.txt"
    local critical_file="$vuln_dir/critical-${today}.txt"
    local high_file="$vuln_dir/high-${today}.txt"
    local medium_file="$vuln_dir/medium-${today}.txt"

    sort -u "$tmp_vulns" > "$vuln_file"

    # Split by severity
    grep -i "critical" "$vuln_file" > "$critical_file" 2>/dev/null || true
    grep -i "high" "$vuln_file" | grep -v "critical" > "$high_file" 2>/dev/null || true
    grep -i "medium" "$vuln_file" > "$medium_file" 2>/dev/null || true

    local total_vulns=$(wc -l < "$vuln_file")
    local critical_count=$(wc -l < "$critical_file")
    local high_count=$(wc -l < "$high_file")
    local medium_count=$(wc -l < "$medium_file")

    log "Vulnerability scan complete"
    log "Total: $total_vulns | Critical: $critical_count | High: $high_count | Medium: $medium_count"

    # Alert immediately on critical vulnerabilities
    if [[ -s "$critical_file" ]]; then
        log "CRITICAL VULNERABILITIES FOUND!"
        local alert_file="$PIPELINE_DIR/alerts/critical-vulns-${today}.txt"
        cp "$critical_file" "$alert_file"

        if command -v notify &>/dev/null && [[ -f "$PIPELINE_DIR/config/notify-config.yaml" ]]; then
            notify -bulk -data "$alert_file" -config "$PIPELINE_DIR/config/notify-config.yaml" 2>/dev/null || true
        fi
    fi

    rm -f "$tmp_vulns"

    log "Results saved to: $vuln_dir/"
}

main "$@"