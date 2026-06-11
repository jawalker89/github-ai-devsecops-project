import json

with open(
    "reports/trivy-results.json"
) as f:
    before = json.load(f)

with open(
    "reports/trivy-results-after.json"
) as f:
    after = json.load(f)


def count_vulns(report):

    count = 0

    for result in report.get(
        "Results",
        []
    ):
        count += len(
            result.get(
                "Vulnerabilities",
                []
            )
        )

    return count


before_count = count_vulns(before)
after_count = count_vulns(after)

print(
    f"Before: {before_count}"
)

print(
    f"After: {after_count}"
)

print(
    f"Fixed: "
    f"{before_count - after_count}"
)
