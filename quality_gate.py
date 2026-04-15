#!/usr/bin/env python3
"""
quality_gate.py - SSDLC-F PR Blocker
Evalua SAST + SCA + DAST + Secrets segun nivel de madurez OWASP SAMM
"""

import json, sys, argparse, os

THRESHOLDS = {
    "inicial":       {"critical": 999, "high": 999, "secrets": 999},
    "en_desarrollo": {"critical": 0,   "high": 999, "secrets": 0  },
    "optimizado":    {"critical": 0,   "high": 0,   "secrets": 0  },
}

def check_semgrep(path):
    if not os.path.exists(path):
        print(f"  [WARN] No encontrado: {path}")
        return 0, 0
    with open(path) as f:
        data = json.load(f)
    results = data.get("results", [])
    critical = sum(1 for r in results if r.get("extra",{}).get("severity","") == "ERROR")
    high     = sum(1 for r in results if r.get("extra",{}).get("severity","") == "WARNING")
    return critical, high

def check_dependency_check(path):
    if not os.path.exists(path):
        for root, dirs, files in os.walk("sca-results"):
            for f in files:
                if f.endswith(".json"):
                    path = os.path.join(root, f)
                    print(f"  [INFO] SCA JSON encontrado: {path}")
                    break
    if not os.path.exists(path):
        print(f"  [WARN] No encontrado: {path}")
        return 0, 0
    with open(path) as f:
        data = json.load(f)
    critical = high = 0
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulnerabilities", []):
            cvss = (vuln.get("cvssv3") or {}).get("baseScore", 0) or \
                   (vuln.get("cvssv2") or {}).get("score", 0)
            if   cvss >= 9.0: critical += 1
            elif cvss >= 7.0: high     += 1
    return critical, high

def check_zap(path):
    if not os.path.exists(path):
        print(f"  [WARN] No encontrado: {path}")
        return 0, 0
    with open(path) as f:
        data = json.load(f)
    critical = high = 0
    sites = data.get("site", [])
    alerts = sites[0].get("alerts", []) if sites else []
    for alert in alerts:
        risk = alert.get("riskdesc", "").lower()
        if   "critical" in risk: critical += 1
        elif "high"     in risk: high     += 1
    return critical, high

def check_gitleaks(path):
    if not os.path.exists(path):
        print(f"  [WARN] No encontrado: {path}")
        return 0
    try:
        with open(path) as f:
            results = json.load(f)
        return len(results) if isinstance(results, list) else 0
    except:
        return 0

def main():
    parser = argparse.ArgumentParser(description="SSDLC-F Quality Gate")
    parser.add_argument("--maturity",  required=True,
                        choices=["inicial","en_desarrollo","optimizado"])
    parser.add_argument("--semgrep",   default=None)
    parser.add_argument("--depcheck",  default=None)
    parser.add_argument("--zap",       default=None)
    parser.add_argument("--gitleaks",  default=None)
    args = parser.parse_args()

    t = THRESHOLDS[args.maturity]
    total_critical = total_high = total_secrets = 0
    summary = []

    if args.semgrep:
        c, h = check_semgrep(args.semgrep)
        total_critical += c; total_high += h
        summary.append(f"  SAST    (Semgrep)  : {c:4} criticas | {h:4} altas")

    if args.depcheck:
        c, h = check_dependency_check(args.depcheck)
        total_critical += c; total_high += h
        summary.append(f"  SCA     (DepCheck) : {c:4} criticas | {h:4} altas")

    if args.zap:
        c, h = check_zap(args.zap)
        total_critical += c; total_high += h
        summary.append(f"  DAST    (ZAP)      : {c:4} criticas | {h:4} altas")

    if args.gitleaks:
        s = check_gitleaks(args.gitleaks)
        total_secrets += s
        summary.append(f"  Secrets (Gitleaks) : {s:4} secretos expuestos")

    print("\n" + "="*55)
    print(f"  SSDLC-F Quality Gate | Nivel: {args.maturity.upper()}")
    print("="*55)
    print(f"  Umbrales -> criticas: {t['critical']} | "
          f"altas: {t['high']} | secretos: {t['secrets']}")
    print("-"*55)
    for line in summary:
        print(line)
    print("-"*55)
    print(f"  TOTAL -> {total_critical} criticas | "
          f"{total_high} altas | {total_secrets} secretos")
    print("="*55)

    failed = (
        total_critical > t["critical"] or
        total_high     > t["high"]     or
        total_secrets  > t["secrets"]
    )

    if failed:
        print("\n  QUALITY GATE FAILED - Pull Request bloqueado\n")
        sys.exit(1)
    else:
        print("\n  QUALITY GATE PASSED - Pull Request aprobado\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
