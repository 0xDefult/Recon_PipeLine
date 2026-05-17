# Bug Bounty Recon Pipeline

An automated reconnaissance framework for bug bounty hunting with continuous monitoring capabilities.

## 🚀 Features
- **Subdomain Enumeration**: subfinder, amass, assetfinder
- **Live Host Detection**: httpx probing
- **Tech Fingerprinting**: Service and technology detection
- **Port Scanning**: naabu & nmap integration
- **Vuln Scanning**: Nuclei templates with severity filtering
- **OSINT**: Cert transparency, Google dorks, Shodan
- **Notifications**: Telegram, Discord, and Slack support

## 🛠️ Setup
1. **Install Dependencies**:
   ```bash
   sudo apt-get install -y golang python3 git curl wget jq nmap unzip
   # Install Go tools: subfinder, httpx, nuclei, naabu, notify, amass, anew, unfurl, gau, assetfinder
   ```
2. **Configure**:
   - Add target domains to `config/targets.txt`.
   - Define authorized domains in `config/scope-whitelist.txt`.
   - Set up notification keys in `config/notify-config.yaml`.

## 💻 Usage
**Run full pipeline:**
```bash
./scripts/recon-master.sh example.com
```

**Run individual modules:**
- Subdomains: `./scripts/subdomain-monitor.sh <domain>`
- Fingerprinting: `./scripts/tech-fingerprint.sh <domain>`
- Port Scan: `./scripts/port-scanner.sh <domain>`
- Vuln Scan: `./scripts/vuln-scan.sh <domain>`
- OSINT: `./scripts/osint-recon.sh <domain>`

## 📂 Structure
- `config/`: Targets, whitelists, and notify settings.
- `scripts/`: Recon modules and orchestrator.
- `data/`: Domain-specific results (ignored by git).
- `logs/`: Execution logs (ignored by git).

⚠️ **Legal Notice**: Only use this tool on targets you have explicit permission to test. Respect rate limits and program rules.
