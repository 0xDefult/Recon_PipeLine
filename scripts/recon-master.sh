#!/bin/bash
#####################################################################
# ETHICAL HACKING TOOL - AUTHORIZED TARGETS ONLY
# Usage: ./recon-master.sh <domain>
# Rate Limited: Max 10 req/sec to prevent DoS
# Author: Recon Pipeline
# Legal: Only use on targets you have explicit permission to test
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

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

# Check if domain is in whitelist
check_scope() {
    local domain="$1"
    local whitelist="$PIPELINE_DIR/config/scope-whitelist.txt"

    if [[ ! -f "$whitelist" ]]; then
        warn "No whitelist file found, skipping scope check"
        return 0
    fi

    if grep -q "^${domain}$" "$whitelist" 2>/dev/null; then
        return 0
    elif grep -q "^\*.${domain}$" "$whitelist" 2>/dev/null; then
        return 0
    else
        error "Domain $domain is NOT in scope-whitelist.txt"
        error "Add '$domain' to config/scope-whitelist.txt to proceed"
        exit 1
    fi
}

# Create directory structure
setup_dirs() {
    local domain="$1"
    local data_dir="$PIPELINE_DIR/data/$domain"

    mkdir -p "$data_dir"/{subdomains,live-hosts,ports,tech,vulns,osint}
    mkdir -p "$PIPELINE_DIR/logs"
    mkdir -p "$PIPELINE_DIR/alerts"

    log "Directory structure created for $domain"
}

# Main recon flow
main() {
    local domain="${1:-}"

    if [[ -z "$domain" ]]; then
        echo "Usage: $0 <domain>"
        echo "Example: $0 example.com"
        exit 1
    fi

    log "========================================="
    log "Starting recon on: $domain"
    log "========================================="

    # Scope check
    check_scope "$domain"

    # Setup directories
    setup_dirs "$domain"

    local timestamp=$(date +%Y-%m-%d)
    local log_file="$PIPELINE_DIR/logs/${timestamp}-${domain}.log"

    exec > >(tee -a "$log_file")
    exec 2>&1

    # Phase 1: Subdomain enumeration
    log "Phase 1: Subdomain Enumeration"
    "$SCRIPT_DIR/subdomain-monitor.sh" "$domain"

    # Phase 2: Technology fingerprinting
    log "Phase 2: Technology Fingerprinting"
    "$SCRIPT_DIR/tech-fingerprint.sh" "$domain"

    # Phase 3: Port scanning
    log "Phase 3: Port Scanning"
    "$SCRIPT_DIR/port-scanner.sh" "$domain"

    # Phase 4: Vulnerability scanning
    log "Phase 4: Vulnerability Scanning"
    "$SCRIPT_DIR/vuln-scan.sh" "$domain"

    # Phase 5: OSINT gathering
    log "Phase 5: OSINT Gathering"
    "$SCRIPT_DIR/osint-recon.sh" "$domain"

    # Generate summary
    log "Generating summary report..."

    local summary="$PIPELINE_DIR/data/$domain/summary-${timestamp}.txt"
    {
        echo "========================================="
        echo "RECON SUMMARY - $domain"
        echo "Date: $(date)"
        echo "========================================="
        echo ""
        echo "Subdomains Found:"
        [[ -f "$PIPELINE_DIR/data/$domain/subdomains/${timestamp}.txt" ]] && wc -l < "$PIPELINE_DIR/data/$domain/subdomains/${timestamp}.txt" || echo "0"
        echo ""
        echo "Live Hosts:"
        [[ -f "$PIPELINE_DIR/data/$domain/live-hosts/${timestamp}.txt" ]] && wc -l < "$PIPELINE_DIR/data/$domain/live-hosts/${timestamp}.txt" || echo "0"
        echo ""
        echo "Vulnerabilities Found:"
        [[ -f "$PIPELINE_DIR/data/$domain/vulns/${timestamp}.txt" ]] && wc -l < "$PIPELINE_DIR/data/$domain/vulns/${timestamp}.txt" || echo "0"
        echo ""
    } > "$summary"

    log "========================================="
    log "Recon completed for: $domain"
    log "Results saved to: $PIPELINE_DIR/data/$domain/"
    log "Log file: $log_file"
    log "========================================="

    # Send notification
    if command -v notify &>/dev/null && [[ -f "$PIPELINE_DIR/config/notify-config.yaml" ]]; then
        log "Sending notification..."
        notify -bulk -data "$summary" -config "$PIPELINE_DIR/config/notify-config.yaml" 2>/dev/null || true
    fi
}

main "$@"