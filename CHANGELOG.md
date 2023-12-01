# Changelog

## v0.2.0 - 2023-12-01

- fix!: switch runtime environment key to `providers` (BREAKING CHANGE)
- fix: ensure `Ueberauth.Failure.Error` message is a binary
- feat: (optional) verify returned scopes
- feat: verify PKCE, nonce, and redirect_uri

## v0.1.0 - 2023-11-29

- fix: wrap raw_info in a struct to avoid logging the opts
- chore: update to Oidcc 3.1.0
- fix: fail if the ID token has an invalid nonce
- feat: support none alg for the ID token (if Userinfo is fetched)
- feat: support Elixir 1.14.4

## v0.1.0-rc.0 - 2023-11-21

- Initial release
