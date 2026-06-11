#!/usr/bin/env python3

import json
import os
import subprocess
import sys
from pathlib import Path
from packaging.version import Version
import shutil

npm_executable = (
    shutil.which("npm.cmd")
    or shutil.which("npm")
)    

if npm_executable is None:
    raise RuntimeError(
        "npm.cmd not found on PATH"
    )

print(
    "npm executable:",
    npm_executable
)

print(
    f"Using npm: {npm_executable}"
)

SEVERITIES_TO_REMEDIATE = [
    "HIGH",
    "CRITICAL"
]


def load_trivy_results(report_file):

    with open(report_file, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_vulnerabilities(trivy_json):

    findings = []

    for result in trivy_json.get("Results", []):

        if result.get("Type") != "node-pkg":
            continue

        vulnerabilities = result.get(
            "Vulnerabilities",
            []
        )

        for vuln in vulnerabilities:

            fixed_version = vuln.get("FixedVersion", "")

            if "," in fixed_version:
                fixed_version = fixed_version.split(",")[0].strip()

            findings.append({
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": fixed_version,
                "severity": vuln.get("Severity"),
                "cve": vuln.get("VulnerabilityID")
            })

    return findings


def build_remediation_plan(vulnerabilities):

    package_updates = {}

    for vuln in vulnerabilities:

        severity = vuln["severity"]

        if severity not in SEVERITIES_TO_REMEDIATE:
            continue

        fixed_version = vuln["fixed_version"]

        if not fixed_version:
            continue

        package_name = vuln["package"]

        current_update = package_updates.get(
            package_name
        )

        if current_update is None:

            package_updates[
                package_name
            ] = vuln

            continue

        try:

            current_version = Version(
                current_update["fixed_version"]
            )

            candidate_version = Version(
                fixed_version
            )

            if candidate_version > current_version:

                package_updates[
                    package_name
                ] = vuln

        except Exception:

            pass

    remediation_plan = []

    for package_name, vuln in (
        package_updates.items()
    ):

        remediation_plan.append({
            "package": package_name,
            "current_version":
                vuln["installed_version"],
            "target_version":
                vuln["fixed_version"],
            "severity":
                vuln["severity"],
            "cve":
                vuln["cve"]
        })

    return remediation_plan


def print_plan(plan):

    print("\n=== Remediation Plan ===\n")

    if not plan:
        print(
            "No HIGH or CRITICAL vulnerabilities found."
        )
        return

    for item in plan:

        print(
            f"Package: {item['package']}"
        )

        print(
            f"Current Version: "
            f"{item['current_version']}"
        )

        print(
            f"Target Version: "
            f"{item['target_version']}"
        )

        print(
            f"Severity: "
            f"{item['severity']}"
        )

        print(
            f"CVE: "
            f"{item['cve']}"
        )

        print("-" * 40)


def update_npm_package(
    package_name,
    version,
    app_directory
):

    print(
        f"\nUpdating "
        f"{package_name} -> {version}"
    )

    print(
        f"App directory: {app_directory}"
    )

    print(
        f"Exists: {Path(app_directory).exists()}"
    )

    print(
    [
        npm_executable,
        "install",
        f"{package_name}@{version}"
    ]
)

    subprocess.run(
        [
            npm_executable,
            "install",
            f"{package_name}@{version}"
        ],
        cwd=app_directory,
        check=True
    )

def verify_with_npm_audit(
    app_directory
):

    print(
        "\n=== Running npm audit ===\n"
    )

    subprocess.run(
        [
            npm_executable,
            "audit"
        ],
        cwd=app_directory,
        check=False
    )    


def apply_remediation(
    plan,
    app_directory
):

    if not plan:
        return

    for item in plan:

        update_npm_package(
            item["package"],
            item["target_version"],
            app_directory
        )


def main():

    project_root = Path(__file__).resolve().parent.parent

    if len(sys.argv) < 2:
        print(
             "Usage: remediation_agent.py <trivy-report>"
        )
        sys.exit(1)

    report_file = Path(sys.argv[1])

    app_directory = (
        project_root /
        "app"
    )

    if not report_file.exists():

        print(
            f"Report not found: "
            f"{report_file}"
        )

        sys.exit(1)

    trivy_results = load_trivy_results(
        report_file
    )

    vulnerabilities = (
        extract_vulnerabilities(
            trivy_results
        )
    )

    remediation_plan = (
        build_remediation_plan(
            vulnerabilities
        )
    )

    print_plan(
        remediation_plan
    )

    apply_remediation(
        remediation_plan,
        app_directory
    )

    verify_with_npm_audit(
    app_directory
    
    )

    print(
        "\nRemediation complete."
    )


if __name__ == "__main__":
    main()