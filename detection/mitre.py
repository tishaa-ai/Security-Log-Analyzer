"""MITRE ATT&CK techniques used by this project.

Only techniques that the available log evidence can genuinely support are
listed. A mapping means the *observed indicator is consistent with* the
technique - it never confirms that an attack happened.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.technique_id.replace(".", "/") + "/"


TECHNIQUES: dict[str, Technique] = {
    "T1110": Technique("T1110", "Brute Force", ("Credential Access",)),
    "T1110.001": Technique("T1110.001", "Brute Force: Password Guessing", ("Credential Access",)),
    "T1110.003": Technique("T1110.003", "Brute Force: Password Spraying", ("Credential Access",)),
    "T1078": Technique(
        "T1078", "Valid Accounts",
        ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"),
    ),
    "T1595.003": Technique("T1595.003", "Active Scanning: Wordlist Scanning", ("Reconnaissance",)),
    "T1190": Technique("T1190", "Exploit Public-Facing Application", ("Initial Access",)),
}


def mapping(technique_id: str, rationale: str) -> dict[str, Any]:
    """Build the MITRE mapping dict stored with an alert."""
    tech = TECHNIQUES[technique_id]
    return {
        "technique_id": tech.technique_id,
        "name": tech.name,
        "tactics": list(tech.tactics),
        "url": tech.url,
        "rationale": rationale,
    }
