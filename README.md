# Web Security Scanning Script

> Passive vulnerability scanner for Laravel & WordPress sites — checks security headers, exposed files, debug modes, and known-vulnerable plugins.

A lightweight, browser-based PHP scanner that performs **read-only / non-intrusive** security checks against a target web application. It detects common misconfigurations and matches detected versions against a CVE database — without firing a single exploit payload.

---

## Legal notice (read this first)

**Only scan websites you own or have written permission to test.**

Unauthorized scanning of third-party websites may violate computer-misuse laws in your jurisdiction (e.g. the Computer Fraud and Abuse Act in the United States, the Computer Misuse Act in the United Kingdom, and similar laws elsewhere).

This tool requires you to tick a consent checkbox before every scan. By using it, you accept full responsibility for ensuring you have authorization to scan the target.

---

## What it does

The scanner runs a chain of **passive** checks against the target URL:

### Generic checks (every site)
- Missing security headers — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Server / X-Powered-By version disclosure
- Exposed sensitive files — `.env`, `.git/config`, `.DS_Store`, `composer.lock`, `package.json`, `phpinfo.php`, backup archives

### Laravel-specific checks
- `APP_DEBUG=true` in production (with stack trace exposure)
- Publicly accessible Laravel Telescope
- Publicly accessible Laravel Horizon
- Exposed Laravel Debugbar
- Laravel version disclosure

### WordPress-specific checks
- WordPress version detection (meta tag + RSS fallback)
- **Plugin enumeration** from page source
- **CVE matching** against detected plugin versions
- `xmlrpc.php` exposure (brute-force amplification vector)
- User enumeration via REST API (`/wp-json/wp/v2/users`)
- `/readme.html` accessibility

### Reporting
Each finding includes:
- Severity (Critical / High / Medium / Low)
- What was observed
- The attack vector that exploits it
- The remediation step

---

## What it does NOT do

This scanner is deliberately scoped to passive recon. It will not:

- Fire SQLi / XSS / RCE payloads against the target
- Attempt logins or brute-force credentials
- Upload files or POST data to the target
- Perform DoS or rate-flood the target

If you need active testing, use a dedicated pentest framework with proper engagement scoping — [OWASP ZAP](https://www.zaproxy.org/), [Burp Suite](https://portswigger.net/burp), [Nuclei](https://github.com/projectdiscovery/nuclei), or [WPScan](https://wpscan.com/).

---

## Requirements

- PHP **8.0+** (uses `match`, `str_contains`, named arguments)
- PHP cURL extension (bundled with XAMPP)
- A webserver — Apache (XAMPP / WAMP / MAMP) or `php -S` works fine

---

## Installation

### Option 1 — XAMPP (recommended for beginners)

1. Install [XAMPP](https://www.apachefriends.org/).
2. Clone this repo into `htdocs/`:
   ```bash
   cd C:/xampp/htdocs
   git clone https://github.com/RaashidMalla/Web-Security-Scanning-Script.git
   ```
3. Start Apache from the XAMPP control panel.
4. Open `http://localhost/Web-Security-Scanning-Script/` in your browser.

### Option 2 — Built-in PHP server

```bash
git clone https://github.com/RaashidMalla/Web-Security-Scanning-Script.git
cd Web-Security-Scanning-Script
php -S localhost:8000
```

Then open `http://localhost:8000/`.

---

## Usage

1. Open the scanner in your browser.
2. Enter the target URL (e.g. `https://my-site.test`).
3. Tick the **"I confirm I am authorized to scan this target"** checkbox.
4. Click **Run Scan**.
5. Review the report — findings are sorted Critical → Low.

### Example output

```
Detected stack: WordPress       Version: 6.2.1       Findings: 7

CRITICAL  .env file exposed
          APP_KEY and DB credentials are publicly readable.
          Attack: full credential takeover.
          Fix:    move .env outside docroot, rotate all secrets.

HIGH      Vulnerable plugin: contact-form-7 v5.3.1
          CVE-2020-35489 — Unrestricted file upload bypass.
          Attack: upload disguised .php for RCE.
          Fix:    update Contact Form 7 to ≥5.3.2.

MEDIUM    Missing Content-Security-Policy
          ...
```

---

## Project structure

```
Web-Security-Scanning-Script/
├── index.php                       # Web UI + form handler
├── lib/
│   ├── Scanner.php                 # Orchestrator
│   ├── Http.php                    # cURL wrapper
│   └── Checks/
│       ├── Headers.php             # Security headers
│       ├── ExposedFiles.php        # Sensitive file probes
│       ├── Laravel.php             # Laravel-specific checks
│       └── WordPress.php           # WordPress-specific checks
├── data/
│   └── wp_plugin_vulns.json        # CVE database (sample)
├── assets/
│   └── style.css                   # Report styling
└── README.md
```

---

## How to extend

### Add a new exposed-file probe
Edit `lib/Checks/ExposedFiles.php` and add a row to the `PATHS` constant. No code changes needed.

### Add a new vulnerable WordPress plugin
Edit `data/wp_plugin_vulns.json` — keys are plugin slugs, values are arrays of vulnerability records.

### Add support for a new framework
1. Create `lib/Checks/Drupal.php` (or whatever) following the same shape as `Laravel.php`.
2. Extend `Scanner::fingerprint()` to detect the new stack.
3. Wire it into `Scanner::run()`.

### Run as a CLI tool
Wrap `Scanner` in a small CLI entry script that reads `$argv[1]` and prints `json_encode($result)`.

---

## Roadmap

- [ ] Auto-sync the WP vulnerability database from the WPScan API
- [ ] Drupal and Joomla check modules
- [ ] JSON output mode for CI/CD pipelines
- [ ] CLI entry point
- [ ] Rate-limiting between requests (be kinder to targets)
- [ ] Scan history with SQLite

---

## Contributing

Pull requests welcome. Good first contributions:

- Add CVE entries to `data/wp_plugin_vulns.json.`
- Add new exposed-file signatures to `lib/Checks/ExposedFiles.php.`
- Improve fingerprinting heuristics in `lib/Scanner.php.`

Please make sure any new check follows the standard finding shape:
```php
[
    'severity' => 'High',
    'title'    => 'Short label',
    'detail'   => 'What was observed',
    'attack'   => 'How it can be abused',
    'fix'      => 'How to remediate',
]
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

This software is provided for **educational purposes** and **authorized security testing only**. The authors accept no liability for misuse. Scanning systems without explicit permission are illegal in most jurisdictions, and this tool is no exception in that regard. Use responsibly.
