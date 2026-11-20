# Security policy — Whyzper.Me / NYRA Sentinel

NYRA Sentinel is security-sensitive software. **Do not disclose unpatched flaws in public issues.**
Use GitHub's **Report a vulnerability** private advisory workflow once the public repository
has enabled private vulnerability reporting. If unavailable, contact the repository maintainer
through a non-public channel specified in the repository profile; do not email invented addresses.

Supported branch: current `main` and explicitly tagged releases only. There is no SLA promise.
Security reports should contain minimal reproduction steps, affected version and impact;
never attach actual user credentials, production log files or VPN configuration.

Threat model: untrusted syslog and DNS content, network polling, local LLM prompt injection,
model-driven tool arguments, compromised API credentials, malicious pull requests and
Docker host privilege. Out of scope: malicious local root/Docker administrators, compromised
container engine/host, and physically exposed systems.

Recommended operation: private management network, distinct scoped secrets, encrypted
backups, pinned images, human approval for defensive changes and frequent vulnerability review.
