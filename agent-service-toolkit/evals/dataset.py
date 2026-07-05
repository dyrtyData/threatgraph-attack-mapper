"""Threat-intel evaluation dataset (PF-001 Phase 5).

A small, hand-curated set of threat-intel snippets with *known* expected properties —
the canonical MITRE ATT&CK technique ids the ``threatgraph`` extractor should surface and
the mitigation ids a faithful defense config should ground against. Every ``technique_id``
and ``mitigation_id`` below is a real ATT&CK id, so the expectations are checkable.

Cases reuse the walking-skeleton seed kill-chain (ransomware phishing) plus several
distinct, multi-tactic incidents (e.g. the APT29 / Mimikatz / RDP / cloud-exfil case) so
the evaluators exercise a range of kill chains rather than a single scenario.

This module is pure data (no Langfuse / network at import) so it is safe to import in tests
and reuse from :mod:`run_experiment`.
"""

from __future__ import annotations

from typing import Any

# The Langfuse dataset name (created / re-used by run_experiment.py).
DATASET_NAME = "threatgraph-mvp"

# Each case:
#   name             short slug used as a stable dataset-item hint
#   input            the raw threat-intel text fed to the graph (the task input)
#   technique_ids    ground-truth ATT&CK technique ids the extractor should surface
#   mitigation_ids   ground-truth ATT&CK mitigation ids a faithful defense config grounds on
#   metadata         free-form tags (surfaced in the Langfuse UI)
THREAT_INTEL_CASES: list[dict[str, Any]] = [
    {
        "name": "ransomware-phishing",
        "input": (
            "An employee received a spearphishing email carrying a macro-enabled Word "
            "attachment. Opening the document and enabling content ran a malicious macro that "
            "launched an encoded PowerShell downloader. The payload then encrypted files across "
            "shared drives and dropped a ransom note demanding payment."
        ),
        "technique_ids": ["T1566.001", "T1204.002", "T1059.001", "T1486"],
        "mitigation_ids": ["M1017", "M1038", "M1042", "M1053"],
        "metadata": {"scenario": "ransomware", "tactics": "initial-access→execution→impact"},
    },
    {
        "name": "apt29-mimikatz-rdp-exfil",
        "input": (
            "An APT29-attributed intrusion began after the actor gained a foothold on a "
            "workstation. They ran Mimikatz to dump credentials from LSASS memory, then used the "
            "stolen administrator credentials to move laterally over RDP to a file server. "
            "Sensitive documents were staged and exfiltrated to an attacker-controlled cloud "
            "storage account."
        ),
        "technique_ids": ["T1003.001", "T1021.001", "T1567.002"],
        "mitigation_ids": ["M1043", "M1032", "M1057"],
        "metadata": {"scenario": "apt29", "tactics": "cred-access→lateral→exfil"},
    },
    {
        "name": "exploit-webshell-persistence",
        "input": (
            "Attackers exploited a vulnerability in an internet-facing web application to gain "
            "initial access. They deployed a web shell to maintain persistence and used it to run "
            "operating-system commands, then created a new local account to retain access."
        ),
        "technique_ids": ["T1190", "T1505.003", "T1136.001"],
        "mitigation_ids": ["M1051", "M1042", "M1026"],
        "metadata": {"scenario": "web-exploit", "tactics": "initial-access→persistence"},
    },
    {
        "name": "brute-force-rdp-defense-evasion",
        "input": (
            "An external actor ran a brute-force password-guessing campaign against the "
            "organization's internet-exposed Remote Desktop service. After guessing valid "
            "credentials they logged in over RDP and disabled endpoint security tools before "
            "deploying additional malware."
        ),
        "technique_ids": ["T1110", "T1021.001", "T1562.001"],
        "mitigation_ids": ["M1032", "M1036", "M1042"],
        "metadata": {"scenario": "brute-force", "tactics": "cred-access→lateral→defense-evasion"},
    },
    {
        "name": "spearphishing-link-valid-accounts",
        "input": (
            "A targeted user clicked a link in a spearphishing email that led to a "
            "credential-harvesting page. The attacker then authenticated to the corporate VPN "
            "using the harvested valid-account credentials and collected internal email."
        ),
        "technique_ids": ["T1566.002", "T1078", "T1114"],
        "mitigation_ids": ["M1017", "M1032", "M1054"],
        "metadata": {"scenario": "credential-phishing", "tactics": "initial-access→collection"},
    },
]


def expected_output(case: dict[str, Any]) -> dict[str, Any]:
    """The ``expected_output`` payload stored on each Langfuse dataset item.

    Kept as a plain dict of the two ground-truth id sets so the SDK evaluators can read
    ``expected["technique_ids"]`` / ``expected["mitigation_ids"]`` directly.
    """
    return {
        "technique_ids": list(case["technique_ids"]),
        "mitigation_ids": list(case["mitigation_ids"]),
    }
