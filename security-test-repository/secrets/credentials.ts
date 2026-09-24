export const CLOUD_CONFIG = {
  // VULNERABLE: Hardcoded secrets and credentials in source code
  AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
  AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  GITHUB_PERSONAL_TOKEN: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
  DATABASE_URI: 'postgres://admin:SuperSecretPassword123@prod-db.internal:5432/kmg_prod'
};
