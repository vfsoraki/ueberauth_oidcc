# Changelog

## v0.4.0 - TBD

- feat!: add `introspection` opt for fetching Token Introspection
- feat: support [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/oauth-v2-jarm-final.html)
- feat: store session data in a separate UeberauthOidcc cookie
- fix: support multiple issuers
- fix: use `client_secret` when generating request URLs
- fix: limit `nonce` to 43 characters

BREAKING CHANGE: the API for `UeberauthOidcc.Callback.handle_callback/2`
has changed to make the 4th item in the tuple a map, rather than only
the userinfo claims.

## v0.3.1 - 2023-12-10

- fix: refresh JWKs if needed (#5)

## v0.3.0 - 2023-12-05

The big change in 0.3.0 is refactoring the implementation into various
sub-modules. This allows them to serve as implementations for other Ueberauth
strategies which use OIDC, by passing in different opts.

- feat: support overriding the token_endpoint
- doc: add the `uid_field` to the list of options
- feat: add some additional error descriptions
- refactor!: pull implementation into UeberauthOidcc modules

BREAKING CHANGE: if you were using `module` for testing, you'll need to
implement some additional sub-modules: `ClientContext`, `Authorization`, `Token`
and `Userinfo`.

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
