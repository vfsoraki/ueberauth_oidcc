# UeberauthOidcc

![pipeline status badge](https://gitlab.com/paulswartz/ueberauth_oidcc/badges/main/pipeline.svg)
![coverage badge](https://gitlab.com/paulswartz/ueberauth_oidcc/badges/main/coverage.svg)
![latest release badge](https://gitlab.com/paulswartz/ueberauth_oidcc/-/badges/release.svg)

`UeberauthOidcc` is two things:

- an implementation of [Ueberauth.Strategy](https://hexdocs.pm/ueberauth/Ueberauth.Strategy.html) based on the [Oidcc](https://hexdocs.pm/oidcc/readme.html) library
- a set of modules for implementing other OpenID Connect (OIDC) strategies

## Installation

The package can be installed by adding `ueberauth_oidcc` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ueberauth_oidcc, "~> 0.3"}
  ]
end
```

## Configuration

1. Add an OIDC Issuer to your Ueberauth configuration.

An issuer is a single OIDC endpoint, but it can be shared by multiple
`Ueberauth.Strategy.Oidcc` providers.

``` elixir
config :ueberauth_oidcc, :issuers, [
  %{name: :oidcc_issuer, issuer: "<issuer URI>"}
]
```

The issuer must provide OIDC configuration at `<issuer URI>/.well-known/openid-configuration`.

See
[oidcc_provider_configuration:opts/0](https://hexdocs.pm/oidcc/oidcc_provider_configuration.html#t:opts/0) for issuer parameters.

2. Add the `Ueberauth.Strategy.Oidcc` strategy to your configuration.

See [UeberauthOidcc.Config](https://hexdocs.pm/ueberauth_oidcc/UeberauthOidcc.Config.html) for supported options.

```elixir
config :ueberauth, Ueberauth,
  providers: [
    oidc: { Ueberauth.Strategy.Oidcc,
      issuer: :oidcc_issuer, # matches the name above
      client_id: "client_id",
      client_secret: "123456789",
      scopes: ["openid", "profile", "email"],
      # optional
      callback_path: "/auth/oidc/callback",
      userinfo: true, # whether to pull info from the Userinfo endpoint, default: false
      validate_scopes: true, # whether to validate the returned scopes are a subset of those request, default: false
      uid_field: "email", # pulled from the merge of the claims and userinfo (if fetched), default: sub
      authorization_params: %{}, # additional parameters for the authorization request
      authorization_params_passthrough: [], # params to pass through from the incoming request (such as "prompt")
      authorization_endpoint: "https://oidc-override/request" # override the initial request URI
    }
  ]
```
The core Ueberauth configuration is only read at compile time, so if you have runtime configuration you'll need to use one of two approaches:

1. Use a `{module, fun, args}` tuple or `{:system, <env var>}` tuple.

``` elixir
config :ueberauth, Ueberauth,
  providers: [
    oidc: { Ueberauth.Strategy.Oidcc,
      issuer: :oidcc_issuer,
      client_id: {:system, "CLIENT_ID"},
      client_secret: {System, :get_env, ["CLIENT_SECRET"]}
    }
  ]
```

2. Put it under the `:ueberauth_oidcc` `:providers` config. 

```elixir
 # config/runtime.exs
 config :ueberauth_oidcc, :providers,
  oidc: [
    client_secret: System.fetch_env!("OIDC_CLIENT_SECRET")
  ]
```

## Usage

1. Include the Ueberauth plug in your controller:

```elixir
defmodule MyApp.AuthController do
  use MyApp.Web, :controller
  plug Ueberauth
  ...
end
```

2. Create the request and callback routes if you haven't already:

```elixir
scope "/auth", MyApp do
  pipe_through :browser

  get "/:unused", AuthController, :request
  get "/:unused/callback", AuthController, :callback
end
```

3. Your controller needs to implement `callback/2` to deal with `Ueberauth.Auth`
and `Ueberauth.Failure` responses. For an example implementation see the
[Ueberauth Example](https://github.com/ueberauth/ueberauth_example) application.

   - `Ueberauth.Auth.Credentials` contains the `access_token` and related fields
     - The `other` map in `Ueberauth.Auth.Credentials` contains `id_token`
   - `Ueberauth.Auth.Extra` contains the raw claims, userinfo, and options

## Calling

Depending on the configured url, you can initialize the request through:

    /auth/oidc

## Documentation

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and or found at <https://hexdocs.pm/ueberauth_oidcc>.

## License

Released under the MIT License. Please see [LICENSE](./LICENSE) for details.


