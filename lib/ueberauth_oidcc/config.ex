defmodule UeberauthOidcc.Config do
  @moduledoc """
  Functions for managing the configuration passed to request/callback modules.

  See `t:t/0` for the supported values.
  """

  @typedoc """
  Configuration taken by the request/callback modules.

  **Required**:
  - issuer: the name of an `Oidcc.ProviderConfiguration.Worker` to use for configuration
  - client_id: the client ID to use
  - client_secret: the client secret to use
  - redirect_uri: the full URI to redirect back to after authentication

  __Optional__:
  - session_cookie: name of cookie used store data between the request and callback (default: `"_ueberauth_strategy_oidcc"`)
  - session_key: secret name to use with `Plug.Crypto.encrypt/4` (default: `"ueberauth_strategy_oidcc"`)
  - session_max_age: maximum number of seconds allowed between the request and callback (default: `3600`)
  - session_same_site: SameSite value to use for the session cookie (default: `"Lax"`)
  - scopes: list of scopes to request (default: `["openid"]`)
  - authorization_params: map of additional parameters to pass in the query to the authorization_endpoint
  - authorization_params_passthrough: list of params which can be passed through from the initial request
  - authorization_endpoint: override the authorization_endpoint defined by the issuer
  - token_endpoint: override the token_endpoint defined by the issuer
  - userinfo: whether to request the userinfo endpoint (default: `false`)
  - userinfo_endpoint: override the userinfo_endpoint defined by the issuer
  - validate_scopes: whether to validate that the returned scopes are a subset of the requested scopes (default: `false`)

  The `session_cookie` name will also be prefixed with `__Secure-` if the
  request comes over HTTPS to ensure that browsers only send it securely.

  You can also give any options taken by the `Oidcc.create_redirect_url/4` or
  `Oidcc.retrieve_token/5` functions.

  For testing:
  - module: (default: `Oidcc`)
  - response_type: (default: `"code"`)
  """
  @type t() :: %{
          # required
          required(:issuer) => atom(),
          required(:client_id) => binary(),
          required(:client_secret) => binary(),
          required(:redirect_uri) => binary(),
          # authorization
          optional(:session_cookie) => binary(),
          optional(:session_key) => binary(),
          optional(:session_max_age) => pos_integer(),
          optional(:session_same_site) => binary(),
          optional(:scopes) => :oidcc_scope.scopes(),
          optional(:authorization_params) => Enumerable.t(),
          optional(:authorization_params_passthrough) => Enumerable.t(),
          optional(:authorization_endpoint) => binary(),
          # callback
          optional(:token_endpoint) => binary(),
          optional(:userinfo) => boolean(),
          optional(:userinfo_endpoint) => binary(),
          optional(:introspection) => boolean(),
          optional(:introspection_endpoint) => binary(),
          # testing
          optional(:module) => module(),
          optional(:response_type) => binary(),
          # extra
          optional(atom) => term()
        }

  @doc """
  Default options for UeberauthOidcc.
  """
  @spec default() :: map()
  def default do
    %{
      module: Oidcc,
      response_type: "code",
      scopes: ["openid"],
      userinfo: false,
      introspection: false,
      validate_scopes: false,
      session_key: "ueberauth_strategy_oidcc",
      session_cookie: "_ueberauth_strategy_oidcc",
      session_max_age: 3600,
      session_same_site: "Lax"
    }
  end

  @doc """
  Given a list of configurations (either as maps or keyword lists), merges them together.

  This starts with the default options (see `default/0`), and merges each
  configuration one at a time, taking the last value.

  In addition to bare values (strings, atoms, numbers), some other types are accepted:
  - a 0-arity function
  - `{:system, <env var>}` which will use the value of the environment variable if it's defined
  - `{:system, <env var>, <default>}` which will use the value of the environment variable if defined, otherwise the default
  - `{mod, fun, args}` which will apply the given MFA tuple
  """
  @spec merge_and_expand_configuration(Enumerable.t()) :: t()
  def merge_and_expand_configuration(configurations) do
    Enum.reduce(configurations, default(), &merge_and_expand_one_configuration/2)
  end

  defp merge_and_expand_one_configuration(config, opts) do
    new_opts =
      config
      |> Enum.flat_map(&expand_configuration/1)
      |> Map.new()

    Map.merge(opts, new_opts)
  end

  defp expand_configuration(key_value)

  defp expand_configuration({key, {:system, env_var}}) do
    case System.fetch_env(env_var) do
      {:ok, value} ->
        [{key, value}]

      :error ->
        # don't use the value if it's not defined
        []
    end
  end

  defp expand_configuration({key, {:system, env_var, default}}) do
    value = System.get_env(env_var) || default
    [{key, value}]
  end

  defp expand_configuration({key, {mod, fun, args}}) do
    [{key, apply(mod, fun, args)}]
  end

  defp expand_configuration({key, fun}) when is_function(fun, 0) do
    [{key, fun.()}]
  end

  defp expand_configuration({key, value}) do
    [{key, value}]
  end
end
