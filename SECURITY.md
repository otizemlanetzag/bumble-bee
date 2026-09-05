# Bumble Bee Security Policy

Bumble Bee follows a defense-in-depth security model. Security controls should fail closed where practical and must not silently weaken browser security for convenience.

## Security layers

- dependency and security-advisory checks in CI;
- supply-chain and license checks;
- Rust formatting and test gates;
- explicit review of unsafe code;
- least-privilege GitHub Actions permissions;
- privacy-oriented browser data lifetime policies;
- automatic deletion of the complete public and private cookie stores every 60 minutes while the browser is running.

## Cookie cleanup policy

Bumble Bee enforces a one-hour cookie lifetime at the desktop application layer. A dedicated timer thread only requests cleanup and wakes Servo's event loop; the actual deletion is performed by Servo's `SiteDataManager` on the Servo event-loop thread.

The cleanup calls `SiteDataManager::clear_cookies(None)`. In this fork that method clears both the public and private cookie jars, so the operation is a real deletion of the complete cookie stores rather than deletion of cookies for only the current site.

The first automatic cleanup occurs one hour after the browser starts. Closing the browser stops the timer cleanly. A cleanup request is also logged after the deletion is performed.

This policy intentionally does not claim to delete other browser state such as HTTP cache, localStorage, or sessionStorage; those are separate storage categories.

## Reporting vulnerabilities

Please report security vulnerabilities privately to the repository owner rather than publishing an exploit or sensitive details in a public issue.

When reporting, include the affected component, reproduction steps, expected security boundary, and the smallest useful proof of impact. Do not include passwords, tokens, private keys, or other secrets.

## License boundary

Security tooling added as an independent component is licensed under GNU GPL version 3 or later. Existing Servo-derived source retains its applicable upstream license and notices. Adding GPL-licensed tooling does not relicense third-party Servo source.
