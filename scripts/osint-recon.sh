#!/bin/bash
#####################################################################
# ETHICAL HACKING TOOL - AUTHORIZED TARGETS ONLY
# OSINT Reconnaissance Script
# Usage: ./osint-recon.sh <domain>
# Rate Limited: Max 10 req/sec to prevent DoS
#####################################################################

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_DIR="$(dirname "$SCRIPT_DIR")"
export PATH="$PATH:$(go env GOPATH)/bin:$HOME/.local/bin"
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
    local osint_dir="$data_dir/osint"
    local output_file="$osint_dir/${today}.txt"
    local crt_file="$osint_dir/crt-sh-${today}.txt"
    local dorks_file="$osint_dir/google-dorks-${today}.txt"

    mkdir -p "$osint_dir"

    log "Starting OSINT gathering for $domain"

    # Query crt.sh for certificate transparency
    log "Querying crt.sh for certificates..."
    curl -s "https://crt.sh/?q=${domain}&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sort -u > "$crt_file" || true

    local crt_count=$(wc -l < "$crt_file")
    log "Found $crt_count certificates from crt.sh"

    # Generate Google dorks
    log "Generating Google dorks..."
    {
        echo "# Google Dorks for $domain"
        echo ""
        echo "site:$domain inurl:login"
        echo "site:$domain inurl:admin"
        echo "site:$domain inurl:config"
        echo "site:$domain inurl:backup"
        echo "site:$domain inurl:.git"
        echo "site:$domain inurl:.env"
        echo "site:$domain inurl:phpinfo"
        echo "site:$domain ext:log"
        echo "site:$domain ext:sql"
        echo "site:$domain ext:db"
        echo "site:$domain filetype:pdf"
        echo "site:$domain intitle:index.of"
    } > "$dorks_file"

    # Generate Shodan queries
    log "Creating Shodan search queries..."
    {
        echo "# Shodan Queries for $domain"
        echo "org:\"$domain\""
        echo "ssl:\"$domain\""
    } >> "$dorks_file"

    # Combine all OSINT data
    {
        echo "========================================="
        echo "OSINT Report - $domain"
        echo "Date: $(date)"
        echo "========================================="
        echo ""
        echo "--- Certificates from crt.sh ---"
        cat "$crt_file"
        echo ""
        echo "--- Google Dorks (see separate file) ---"
        echo "Saved to: $dorks_file"
    } > "$output_file"

    log "OSINT gathering complete"
    log "Results saved to: $osint_dir/"

    # Note about TruffleHog
    if command -v trufflehog &>/dev/null; then
        log "TruffleHog is available"
        log "To scan GitHub repos, run: trufflehog github --org=$domain"
    else
        log "TruffleHog not installed - skipping secret scanning"
        log "Install with: pip install trufflehog"
    fi
}

main "$@"