# Email Provider Scanner

Identifies the email provider of each institution by querying **MX** and **TXT (SPF)**
DNS records via the official Cloudflare DNS over HTTPS (DoH) API.

Built for the thesis *"An Assessment of Web-Related Security in Norwegian Higher
Education Institutions"* (Østfold University College, 2026).

---

## Data availability

**This repository contains code only.** The scan results produced for the thesis
are not published, because they contain per-institution security findings that
cannot be disclosed.

`source/` and `results/` ship empty (with a `.gitkeep` placeholder). Place your
own institution list in `source/` and run the scanner to regenerate output. The
Norwegian and Portuguese HEI lists used in the thesis are published separately as
[hei-norway-dataset](../hei-norway-dataset) and
[hei-portugal-dataset](../hei-portugal-dataset).

---

## API

**Cloudflare DNS over HTTPS — JSON format**

```
GET https://cloudflare-dns.com/dns-query?name=<domain>&type=MX
GET https://cloudflare-dns.com/dns-query?name=<domain>&type=TXT
Accept: application/dns-json
```

- No API key, no registration, no relevant rate limit
- Official docs: https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
- Protocol: RFC 8484 (DNS over HTTPS)
- Response: JSON with `Status`, `Question`, and `Answer` fields

---

## Requirements

- Python 3.10 or newer
- `openpyxl` (`pip install openpyxl`) — for Excel output

---

## Project structure

```
hei-email-provider-scanner/
├── scanner.py          # Main script
├── source/             # Drop your institution CSVs here (ships empty)
└── results/            # Output files written here automatically (ships empty)
```

---

## Usage

```bash
python scanner.py
```

The script will:

1. Read every `.csv` file in `source/`
2. For each institution, query MX and TXT records via Cloudflare DoH
3. Identify the provider based on known fingerprints
4. Print a colour-coded report to the terminal
5. Write a timestamped `.csv` and `.xlsx` to `results/`

---

## Detection logic

The scanner uses two layers of evidence:

### 1. MX records (primary)
The mail server hostname is matched against known provider patterns:

| Provider | MX pattern |
|---|---|
| Microsoft 365 | `mail.protection.outlook.com` |
| Google Workspace | `aspmx.l.google.com`, `googlemail.com` |
| Proofpoint | `pphosted.com` |
| Mimecast | `mimecast.com` |
| Barracuda | `barracudanetworks.com` |
| Zoho Mail | `zoho.com` |
| ProtonMail | `protonmail.ch`, `proton.me` |
| Tutanota | `tutanota.de`, `tuta.io` |
| UNINETT / Sikt | `uninett.no`, `sikt.no` |
| ... | ... |

### 2. TXT / SPF records (secondary)
The SPF record (`v=spf1 ...`) is used as confirmation or as a fallback when
the MX hostname does not match any known pattern.

### Special case: security gateway
When the MX points to a gateway (Proofpoint, Mimecast, Barracuda) but the SPF
reveals a different provider, the `provider` field reflects both:

```
Proofpoint (gateway) / Microsoft 365
```

---

## Output columns

| Column | Description |
|---|---|
| ID, Name, Category, NUTS2, NUTS2_Label, url | Copied from input |
| query_domain | Domain actually queried in DNS |
| provider | Detected email provider |
| confidence | High / Medium / Low / N/A |
| evidence | Justification for the detection |
| note | Additional observation (e.g. gateway, self-hosted) |
| mx_primary | Lowest-priority MX record (primary) |
| mx_all | All MX records sorted by priority |
| spf_record | Full SPF record |

---

## Notes

- The queried domain is extracted from the `url` field in the CSV by stripping
  `www.`, the scheme, and any path. Example: `www.uia.no` → DNS query for `uia.no`
- When no MX record exists, the `provider` field is set to `No MX record`.
- The script waits 0.5 seconds between requests to be respectful to the public API.
