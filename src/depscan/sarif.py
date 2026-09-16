"""SARIF 2.1.0 output generator for depscan.

Converts depscan scan results to OASIS SARIF 2.1.0 format
for GitHub Code Scanning, GitLab Security Dashboard, and CI systems.
"""
from __future__ import annotations

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "moderate": "warning",
    "low": "note",
    "info": "note",
}


def to_sarif(results: dict, version: str = "0.1.0") -> dict:
    """Convert depscan scan results to a SARIF 2.1.0 compliant dictionary."""
    rules = []
    sarif_results = []
    rule_ids = set()

    # Rule: typosquat detection
    typosquats = results.get("typosquats", [])
    if typosquats and "depscan-typosquat" not in rule_ids:
        rule_ids.add("depscan-typosquat")
        rules.append({
            "id": "depscan-typosquat",
            "name": "TyposquatDependency",
            "shortDescription": {
                "text": "Potential typosquatting dependency detected"
            },
            "fullDescription": {
                "text": "A dependency matches a known popular package name with slight typographical variations, indicating potential malicious spoofing."
            },
            "defaultConfiguration": {
                "level": "warning"
            },
            "properties": {
                "tags": ["security", "supply-chain", "typosquat"]
            }
        })

    for dep in typosquats:
        # Issue #3: Typosquat detected (CRITICAL/HIGH) -> error, Potential (MEDIUM) -> warning
        typo_sev = getattr(dep, "typosquat_severity", "high").lower()
        level = "error" if typo_sev in ("critical", "high") else "warning"
        sarif_results.append({
            "ruleId": "depscan-typosquat",
            "level": level,
            "message": {
                "text": f"Dependency '{dep.name}' (v{dep.version}) in {dep.ecosystem} appears to be a typosquat of popular package '{dep.typosquat_target}'."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": getattr(dep, "source_file", None) or "dependencies"
                        }
                    }
                }
            ]
        })

    # Rule: known vulnerabilities
    vulnerable = results.get("vulnerable", [])
    for dep in vulnerable:
        for vuln in getattr(dep, "known_vulnerabilities", []):
            vuln_id = getattr(vuln, "id", "depscan-vulnerability")
            vuln_severity = getattr(vuln, "severity", "medium").lower()
            level = SEVERITY_TO_LEVEL.get(vuln_severity, "warning")

            if "depscan-vulnerability" not in rule_ids:
                rule_ids.add("depscan-vulnerability")
                rules.append({
                    "id": "depscan-vulnerability",
                    "name": "VulnerableDependency",
                    "shortDescription": {
                        "text": "Known vulnerability in dependency"
                    },
                    "defaultConfiguration": {
                        "level": "warning"
                    },
                    "properties": {
                        "tags": ["security", "vulnerability"]
                    }
                })

            sarif_results.append({
                "ruleId": "depscan-vulnerability",
                "level": level,
                "message": {
                    "text": f"{dep.name}@{dep.version}: {vuln_id} - {getattr(vuln, 'description', '')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": getattr(dep, "source_file", None) or "dependencies"
                            }
                        }
                    }
                ]
            })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "depscan",
                        "semanticVersion": version,
                        "informationUri": "https://github.com/yunaremaia/depscan",
                        "rules": rules
                    }
                },
                "results": sarif_results
            }
        ]
    }
