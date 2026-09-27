## What changed and why

## Security impact

<!-- Does this change enforcement, fail-closed behaviour, the installer, or
what runs as root? Say how you tested it. Security fixes belong in a private
advisory first; see SECURITY.md. -->

## Checklist

- [ ] `AllTests` passes locally
- [ ] Shell changes: `bash PKG/tests/test-pam-lib.sh` and `bash PKG/tests/test-sentinel-lib.sh` pass
- [ ] New or changed behaviour has tests
- [ ] Docs updated (README, SECURITY.md, docs/) where behaviour changed
- [ ] No real usernames, serials, hostnames, Jamf URLs or credentials in code or fixtures
