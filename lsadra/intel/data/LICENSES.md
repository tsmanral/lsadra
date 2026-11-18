# Bundled intel: sources and licences

This directory holds the bundled intel tier from ADR 0004: `intel-YYYYMMDD.sqlite`,
its `manifest.json` (file hash, size, per-source versions and record counts), and
`manifest.sig` (Ed25519 signature over the manifest bytes). LSADRA verifies the
signature against `lsadra/intel/trusted_keys.json` and the file hash before it
opens the database, and refuses any manifest that lists a source outside the
allowlist below.

Only sources whose terms allow redistribution are bundled:

| Source | What we use | Licence / terms |
|---|---|---|
| CISA Known Exploited Vulnerabilities (`cisa_kev`) | Full catalog: CVE, vendor, product, dates, ransomware use, required action, CWEs | U.S. Government work; CISA publishes the catalog in the `cisagov/kev-data` repository under CC0 1.0. |
| MITRE ATT&CK Enterprise (`mitre_attack_enterprise`) | Technique and sub-technique IDs, names, tactics, URLs (revoked and deprecated entries dropped) | © The MITRE Corporation. Reproduced under the ATT&CK Terms of Use (royalty-free licence to use, copy and distribute with this notice). See https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ |

Also allowlisted for future bundles: CISA advisories (`cisa_advisories`) and
NVD CVE data (`nvd`, public domain; "This product uses data from the NVD API but
is not endorsed or certified by the NVD").

Never bundled (runtime tier only, kept in the gitignored `intel_runtime.db` or
`data/geo/`): AbuseIPDB, AlienVault OTX, abuse.ch, Spamhaus, MaxMind GeoLite2,
DB-IP Lite, Tor exit lists.
