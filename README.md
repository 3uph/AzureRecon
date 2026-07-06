# AzureRecon

> **This tool is intended for authorized red team operations and internal security audits only.** Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

## Features

- **Email Enumeration** - check if emails exist in a Microsoft tenant without sending passwords or generating any sign-in log
- **MFA Detection** - identify which accounts have MFA enabled, Conditional Access policies, or no second factor at all
- **Password Spraying** - one password across many users per round, with configurable cooldown between rounds to avoid Smart Lockout
- **Bruteforce** - multiple passwords against one or more users, auto-stops on lockout detection
- **OPSEC Warnings** - the tool tells you exactly what will be visible to the blue team before every loud action, and asks for confirmation
- **Visual Output** - color-coded results with status badges, progress tracking, countdown timers and a detailed summary table
- **Output Formats** - terminal, plain text file, or JSON

## OPSEC

AzureRecon uses two different techniques depending on the mode. Understanding the detection surface of each is critical for any engagement.

### GetCredentialType (Stealth)

Used by default in `--enum` mode. Queries the `GetCredentialType` endpoint, which Microsoft uses internally to determine the authentication method for a given user. No authentication attempt is made.

| What happens | Visibility |
|---|---|
| No sign-in log entry generated | Tenant admin sees **nothing** |
| No password sent | No failed auth event |
| No Smart Lockout trigger | No risk detection |
| No Conditional Access evaluation | No SOC alert |

**Only detectable** at the network level if the organization monitors outbound HTTPS traffic to `login.microsoftonline.com` and correlates request volume from a single IP.

### OAuth /token (Loud)

Used in `--mfa`, `--spray`, `--brute` modes and optionally in `--enum --oauth`. Sends actual authentication requests to the Azure AD OAuth2 token endpoint.

| What happens | Visibility |
|---|---|
| Sign-in log entry per attempt | Azure Portal, Entra ID logs |
| IP, User-Agent, client_id logged | SIEM correlation (Sentinel, Splunk) |
| Smart Lockout can trigger | Per-user, per-IP thresholds |
| Identity Protection risk detections | Spray pattern detection |
| Conditional Access evaluated | Location and device anomalies |

The tool shows a detailed OPSEC warning before executing any loud operation and requires explicit confirmation (or `--accept-risk` to suppress).

## Installation

```bash
git clone https://github.com/3uph/AzureRecon.git
cd AzureRecon
pip install requests
```

## Usage

### Email Enumeration (Stealth)

Check if emails exist in a tenant. No passwords, no logs.

```bash
# Single email
python3 azurerecon.py --enum -e user@company.com

# From a list
python3 azurerecon.py --enum -E emails.txt

# Target a specific tenant
python3 azurerecon.py --enum -E emails.txt -t contoso.com

# Tenant by GUID
python3 azurerecon.py --enum -e user@target.com -t 72f988bf-86f1-41af-91ab-2d7cd011db47

# Save results
python3 azurerecon.py --enum -E emails.txt -o results.txt

# JSON output
python3 azurerecon.py --enum -E emails.txt -o results.json --json
```

### Email Enumeration (OAuth)

Uses the token endpoint instead. Louder, but also reveals more info (locked, disabled, expired accounts).

```bash
python3 azurerecon.py --enum --oauth -E emails.txt

# OAuth enum against specific tenant
python3 azurerecon.py --enum --oauth -E emails.txt -t contoso.com
```

### MFA Check

Given valid credentials, check if the account has MFA enabled.

```bash
python3 azurerecon.py --mfa -e user@company.com -p 'Password123!'

# Against specific tenant
python3 azurerecon.py --mfa -e user@company.com -p 'Password123!' -t company.com
```

### Password Spray

One password per round across all users, with a cooldown between rounds to respect Smart Lockout windows.

```bash
# Single password
python3 azurerecon.py --spray -E emails.txt -p 'Summer2026!'

# Multiple passwords (5 min cooldown between rounds)
python3 azurerecon.py --spray -E emails.txt -P passwords.txt

# Custom cooldown and delay
python3 azurerecon.py --spray -E emails.txt -P passwords.txt --delay 2.0 --spray-wait 600

# Spray against specific tenant
python3 azurerecon.py --spray -E emails.txt -p 'Summer2026!' -t target.onmicrosoft.com
```

### Bruteforce

All passwords against each user. Stops per user on valid hit, lockout, or not-found.

```bash
python3 azurerecon.py --brute -e user@company.com -P passwords.txt
```

## Options

| Flag | Description | Default |
|---|---|---|
| `--enum` | Email enumeration mode | — |
| `--mfa` | MFA check mode | — |
| `--spray` | Password spray mode | — |
| `--brute` | Bruteforce mode | — |
| `-e` | Single email | — |
| `-E` | File with emails | — |
| `-p` | Single password | — |
| `-P` | File with passwords | — |
| `-t` | Target tenant domain or GUID | common |
| `--oauth` | Use OAuth endpoint for enum | off |
| `--delay` | Seconds between requests | 0.5 / 1.5 / 2.0 |
| `--spray-wait` | Seconds between spray rounds | 300 |
| `--max-lockouts` | Stop after N lockouts | 3 |
| `--force` | Ignore lockout threshold | off |
| `--accept-risk` | Suppress OPSEC warnings | off |
| `-o` | Write results to file | — |
| `--json` | Output as JSON | off |
| `-v` | Verbose (show failed attempts) | off |

## Tenant Targeting

By default, AzureRecon uses the `common` endpoint, which auto-routes requests to the correct tenant based on the email domain. Use `-t` to target a specific tenant by domain or GUID.

| Mode | Behavior |
|---|---|
| `common` (default) | Microsoft routes to the tenant matching the email domain |
| Specific tenant | Queries that tenant directly — rejects emails that don't belong to it |

Specific tenant is useful for:
- Confirming email membership within a known tenant
- Getting clearer responses from federated tenants (ADFS/Okta)
- Avoiding ambiguous results from the `common` routing

## Azure AD Error Codes

The tool interprets the following Azure AD error codes from authentication responses:

| Code | Status | Meaning |
|---|---|---|
| AADSTS50034 | NOT_FOUND | User does not exist |
| AADSTS50126 | INVALID_PASS | Wrong password (user exists) |
| AADSTS50079 | VALID_MFA | Valid creds, MFA required |
| AADSTS50076 | VALID_MFA | Valid creds, MFA required |
| AADSTS50158 | VALID_CA_MFA | Valid creds, Conditional Access/MFA |
| AADSTS50053 | LOCKED | Smart Lockout triggered |
| AADSTS50057 | DISABLED | Account disabled |
| AADSTS50055 | EXPIRED | Password expired |
| AADSTS50128 | TENANT_NOT_FOUND | Tenant does not exist |
| AADSTS50059 | TENANT_NOT_FOUND | Tenant does not exist |

## Legal Disclaimer

This tool is provided for authorized security testing and educational purposes only. You are responsible for ensuring you have explicit written authorization before testing any system. The author assumes no liability for misuse or damage caused by this tool. Always follow your organization's rules of engagement and applicable laws.

## Author

[@3uph](https://github.com/3uph)
