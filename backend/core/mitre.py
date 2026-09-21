"""
MITRE ATT&CK Framework Mapping Core Module for Asgard Cyber Suite
Maps security events across Heimdall, Sleipnir, Bifrost, Yggdrasil, Mjolnir
and Fenrir to MITRE ATT&CK Techniques.

Coverage rule (same honesty bar as the rest of the suite): a technique is
listed only if a module does something real about it today — detection,
audit finding, intel match or orchestrated response. "active" means the
module detects/blocks it directly; "monitored" means the suite sees it via
intel or playbooks but does not block it by itself.
"""

from typing import Dict, List, Any

# Tactic name -> ATT&CK tactic ID (used to render the dashboard matrix).
TACTIC_IDS = {
    "Reconnaissance": "TA0043",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Impact": "TA0040",
}

MITRE_ATTACK_MATRIX = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force mechanisms to gain access to accounts.",
        "modules": ["Heimdall"],
        "severity": "high",
        "status": "active",
    },
    "T1110.001": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may systematically guess passwords to access accounts.",
        "modules": ["Heimdall"],
        "severity": "medium",
        "status": "active",
    },
    "T1003": {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials (e.g. LSASS memory, SAM) to obtain account login information.",
        "modules": ["Mjolnir"],
        "severity": "critical",
        "status": "active",
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
        "modules": ["Bifrost"],
        "severity": "low",
        "status": "active",
    },
    "T1595": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may execute active reconnaissance scans to gather information about the target.",
        "modules": ["Bifrost"],
        "severity": "low",
        "status": "active",
    },
    "T1018": {
        "id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname or network neighborhood.",
        "modules": ["Bifrost"],
        "severity": "low",
        "status": "active",
    },
    "T1049": {
        "id": "T1049",
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of network connections to or from the compromised system.",
        "modules": ["Mjolnir"],
        "severity": "low",
        "status": "active",
    },
    "T1087.002": {
        "id": "T1087.002",
        "name": "Domain Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of domain accounts, including admins and MFA posture.",
        "modules": ["Yggdrasil"],
        "severity": "medium",
        "status": "active",
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into remote services (RDP, SSH, SMB) exposed on the network.",
        "modules": ["Bifrost", "Yggdrasil"],
        "severity": "medium",
        "status": "monitored",
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obtain and use credentials of existing accounts.",
        "modules": ["Yggdrasil"],
        "severity": "medium",
        "status": "active",
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "modules": ["Sleipnir", "Mjolnir"],
        "severity": "high",
        "status": "monitored",
    },
    "T1204": {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
        "description": "Adversaries may rely on user interaction (e.g. malicious Office macros) to execute code.",
        "modules": ["Mjolnir"],
        "severity": "high",
        "status": "active",
    },
    "T1053": {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Adversaries may abuse task scheduling to establish persistence.",
        "modules": ["Mjolnir"],
        "severity": "high",
        "status": "active",
    },
    "T1112": {
        "id": "T1112",
        "name": "Modify Registry",
        "tactic": "Defense Evasion",
        "description": "Adversaries may modify the Registry (e.g. Run keys) to establish persistence or evade defenses.",
        "modules": ["Mjolnir"],
        "severity": "medium",
        "status": "active",
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may exploit internet-facing services; exposure and known CVEs are correlated from scan and intel data.",
        "modules": ["Bifrost", "Fenrir"],
        "severity": "high",
        "status": "monitored",
    },
    "T1070": {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or modify logs and forensic artifacts to evade detection.",
        "modules": ["Mjolnir"],
        "severity": "medium",
        "status": "monitored",
    },
    "T1562": {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may modify security tools to evade detection.",
        "modules": ["Heimdall", "Mjolnir"],
        "severity": "critical",
        "status": "monitored",
    },
    "T1490": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete backups or leave ransom notes to inhibit recovery (ransomware behavior).",
        "modules": ["Mjolnir"],
        "severity": "critical",
        "status": "active",
    },
}


def get_mitre_coverage() -> Dict[str, Any]:
    """Return MITRE ATT&CK coverage statistics across the Asgard suite."""
    tactics: Dict[str, List[Dict[str, Any]]] = {}
    for tech_id, tech in MITRE_ATTACK_MATRIX.items():
        tactic = tech["tactic"]
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append(tech)
    
    return {
        "total_techniques": len(MITRE_ATTACK_MATRIX),
        "covered_tactics": list(tactics.keys()),
        "tactics": tactics,
        "active_modules": ["Heimdall", "Bifrost", "Yggdrasil", "Fenrir", "Sleipnir", "Mjolnir", "Forseti", "Gjallarhorn", "Ragnarok"]
    }
