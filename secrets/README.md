Put optional upstream credentials here. Do not commit actual files.
Required if enabling adapters:
  adguard_password  - one line with UI user's password
  crowdsec_api_key  - one line with CrowdSec LAPI bouncer API key (read decisions only)
Example permissions: chown root:10001 secrets/{adguard_password,crowdsec_api_key}; chmod 0640 secrets/{adguard_password,crowdsec_api_key}; chmod 0750 secrets
