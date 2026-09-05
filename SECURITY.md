# Bumble Bee Security Policy

Bumble Bee follows a defense-in-depth security model. Security controls should fail closed where practical and must not silently weaken browser security for convenience.

## Security layers

- dependency and security-advisory checks in CI;
- supply-chain and license checks;
- Rust formatting and test gates;
- explicit review of unsafe code;
- least-privilege GitHub Actions permissions;
- privacy-oriented browser data lifetime policies;
- automatic cookie-store cleanup every 60 minutes once connected to the browser cookie-store controller.

## Cookie cleanup policy

Bumble Bee's intended privacy policy is to clear the browser's complete cookie store every 60 minutes.

The current Servo embedder API does not yet expose a stable public API for enumerating and clearing the complete cookie store. Servo is actively extending this API; upstream work specifically tracks exposing all stored cookies to embedders. Until that API is available in the fork, Bumble Bee must not pretend that a generic timer has deleted browser cookies when it has not.

The cleanup layer therefore uses an explicit cookie-store controller interface. When wired to Servo's cookie store, the controller must perform a complete cookie-store deletion rather than only deleting cookies for the current URL.

## Reporting vulnerabilities

Please report security vulnerabilities privately to the repository owner rather than publishing an exploit or sensitive details in a public issue.

When reporting, include the affected component, reproduction steps, expected security boundary, and the smallest useful proof of impact. Do not include passwords, tokens, private keys, or other secrets.

## License boundary

Security tooling added as an independent component is licensed under GNU GPL version 3 or later. Existing Servo-derived source retains its applicable upstream license and notices. Adding GPL-licensed tooling does not relicense third-party Servo source.
