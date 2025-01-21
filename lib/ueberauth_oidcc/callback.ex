defmodule UeberauthOidcc.Callback do
  @moduledoc """
  Support implementation of `c:Ueberauth.Strategy.handle_callback!/1`
  """

  alias UeberauthOidcc.Config
  alias UeberauthOidcc.Session
  import UeberauthOidcc.Helpers

  import Ueberauth.Strategy.Helpers, only: [callback_path: 1, callback_url: 1]

  @doc """
  Support implementation of `c:Ueberauth.Strategy.handle_callback!/1`

  Takes options and the `Plug.Conn.t()`, and returns either an updated
  `Plug.Conn.t()`, a token, userinfo claims, and introspection, or an error (and the
  updated conn).

  See `UeberauthOidcc.Error.set_described_error/3` for help with rendering the
  error.
  """
  @spec handle_callback(UeberauthOidcc.Config.t(), Plug.Conn.t()) ::
          {:ok, Plug.Conn.t(), Oidcc.Token.t(),
           %{
             optional(:userinfo) => :oidcc_jwt_util.claims(),
             optional(:introspection) => Oidcc.TokenIntrospection.t()
           }}
          | {:error, Plug.Conn.t(), term}
  def handle_callback(opts, conn) do
    opts =
      Config.default()
      |> Map.merge(Map.new(opts))
      |> opts_with_refresh()
      |> Map.put_new(:callback_path, callback_path(conn))
      |> Map.put_new(:redirect_uri, callback_url(conn))

    session = Session.get(conn, opts)
    conn = Session.delete(conn, opts)

    conn
    |> retrieve_token(session, opts)
    |> handle_token(conn, session, opts)
  end

  defp retrieve_token(conn, session, opts) do
    userinfo? = opts.userinfo

    nonce =
      case Map.fetch(session, :raw_nonce) do
        {:ok, raw_nonce} -> url_encode64(:crypto.hash(:sha256, raw_nonce))
        :error -> :any
      end

    retrieve_token_params = %{
      nonce: nonce,
      pkce_verifier: Map.get(session, :pkce_verifier, :none),
      redirect_uri: opts.redirect_uri
    }

    provider_overrides = Map.take(opts, [:token_endpoint])

    with :ok <- validate_response_mode(Map.get(session, :response_mode, :any), conn),
         :ok <- validate_redirect_uri(Map.get(session, :redirect_uri, :any), conn),
         :ok <- validate_issuer(Map.get(session, :issuer, :any), opts.issuer),
         {:ok, client_context, opts} <- client_context(opts, provider_overrides),
         {:ok, %{"code" => code} = claims} <-
           claims_from_params(conn.params, client_context, opts),
         :ok <- validate_state(Map.get(session, :state), claims["state"]),
         {:ok, token} <-
           apply_oidcc(opts, [Token], :retrieve, [
             code,
             client_context,
             Map.merge(opts, retrieve_token_params)
           ]) do
      {:ok, token}
    else
      {:error, {:none_alg_used, token}} when userinfo? ->
        # the none algorithm is okay for the ID token if we then verify the
        # userinfo (oidcc-client-test-idtoken-sig-none)
        {:ok, token}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp claims_from_params(%{"code" => _code} = params, client_context, _opts) do
    case validate_iss_param(Map.get(params, "iss"), client_context) do
      :ok ->
        {:ok, params}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp claims_from_params(%{"response" => jarm_response}, client_context, opts) do
    case apply_oidcc(opts, [Token], :validate_jarm, [
           jarm_response,
           client_context,
           opts
         ]) do
      {:ok, %{"code" => _code}} = response -> response
      {:ok, params} -> {:error, {:jarm_error, params}}
      {:error, _} = error -> error
    end
  end

  defp claims_from_params(_params, _client_context, _opts) do
    {:error, :missing_code}
  end

  defp handle_token(maybe_token, conn, session, opts) do
    with {:ok, token} <- maybe_token,
         :ok <-
           validate_token_scopes(token, Map.get(session, :scopes, :any), opts.validate_scopes),
         {:ok, userinfo} <- maybe_userinfo(opts, token),
         {:ok, introspection} <- maybe_introspection(opts, token) do
      additional =
        for {key, value} <- [userinfo: userinfo, introspection: introspection],
            value != nil,
            into: %{},
            do: {key, value}

      {:ok, conn, token, additional}
    else
      {:error, reason} -> {:error, conn, reason}
    end
  end

  defp validate_response_mode(:any, _) do
    :ok
  end

  defp validate_response_mode(response_mode, %Plug.Conn{
         method: "GET",
         params: %{"response" => _}
       })
       when response_mode in ["jwt", "query.jwt"] do
    :ok
  end

  defp validate_response_mode("form_post.jwt", %Plug.Conn{
         method: "POST",
         params: %{"response" => _}
       }) do
    :ok
  end

  defp validate_response_mode("form_post", %Plug.Conn{method: "POST"} = conn) do
    case conn.params do
      %{"response" => _} ->
        # if we did get a JARM but didn't expect it, bail out
        {:error, {:invalid_response_mode, "form_post"}}

      _ ->
        :ok
    end
  end

  defp validate_response_mode("query", %Plug.Conn{method: "GET"} = conn) do
    case conn.params do
      %{"response" => _} ->
        # if we did get a JARM but didn't expect it, bail out
        {:error, {:invalid_response_mode, "query"}}

      _ ->
        :ok
    end
  end

  defp validate_response_mode(mode, _expected) do
    {:error, {:invalid_response_mode, mode}}
  end

  # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
  # > state
  # > RECOMMENDED. Opaque value used to maintain state between the request and
  # > the callback. Typically, Cross-Site Request Forgery (CSRF, XSRF)
  # > mitigation is done by cryptographically binding the value of this
  # > parameter with a browser cookie.
  defp validate_state(state, state) do
    :ok
  end

  defp validate_state(_, _) do
    {:error, :invalid_state}
  end

  # https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#name-mix-up-attacks
  # > [...] clients MUST store, for each authorization request, the issuer
  # > they sent the authorization request to and bind this information to
  # > the user agent.

  # we use a different sentinel here to avoid the `:any` atom overlapping with the name of an actual issuer.
  defp validate_issuer({}, _) do
    :ok
  end

  defp validate_issuer(issuer, issuer) do
    :ok
  end

  defp validate_issuer(issuer, expected) do
    {:error, {:invalid_issuer, issuer, expected}}
  end

  # https://openid.net/specs/openid-financial-api-part-1-1_0.html#public-client
  # > shall store the redirect URI value in the resource owner's user-agents
  # > (such as browser) session and compare it with the redirect URI that the
  # > authorization response was received at, where, if the URIs do not match, the
  # > client shall terminate the process with error
  defp validate_redirect_uri(:any, _) do
    :ok
  end

  defp validate_redirect_uri(uri, conn) do
    # generate the current URL but without the query string parameters
    case Plug.Conn.request_url(%{conn | query_string: ""}) do
      ^uri ->
        :ok

      actual_uri ->
        {:error, {:invalid_redirect_uri, actual_uri}}
    end
  end

  defp validate_token_scopes(token, requested_scopes, validate_scopes?)

  defp validate_token_scopes(_, _, false) do
    :ok
  end

  defp validate_token_scopes(_, :any, _) do
    :ok
  end

  defp validate_token_scopes(token, requested_scopes, true) do
    # https://openid.net/specs/openid-financial-api-part-1-1_0.html#public-client
    # # > shall verify that the scope received in the token response is either
    # > an exact match, or contains a subset of the scope sent in the
    # > authorization request; and
    additional_scopes =
      for scope <- token.scope,
          scope not in requested_scopes do
        scope
      end

    if additional_scopes == [] do
      :ok
    else
      {:error, {:additional_scopes, additional_scopes}}
    end
  end

  defp validate_iss_param(iss, client_context)

  defp validate_iss_param(iss, %{provider_configuration: %{issuer: iss}}) do
    :ok
  end

  defp validate_iss_param(actual, %{provider_configuration: %{issuer: expected}})
       when is_binary(actual) and actual != expected do
    {:error, {:invalid_issuer, actual, expected}}
  end

  defp validate_iss_param(nil, %{
         provider_configuration: %{
           authorization_response_iss_parameter_supported: true
         }
       }) do
    {:error, :missing_issuer}
  end

  defp validate_iss_param(_iss, _context) do
    :ok
  end

  defp maybe_userinfo(%{userinfo: true} = opts, token) do
    provider_overrides = Map.take(opts, [:userinfo_endpoint])

    with {:ok, client_context, opts} <- client_context(opts, provider_overrides) do
      apply_oidcc(opts, [Userinfo], :retrieve, [
        token,
        client_context,
        opts
      ])
    end
  end

  defp maybe_userinfo(_opts, _token) do
    {:ok, nil}
  end

  defp maybe_introspection(%{introspection: true} = opts, token) do
    provider_overrides = Map.take(opts, [:introspection_endpoint])

    with {:ok, client_context, opts} <- client_context(opts, provider_overrides),
         {:ok, introspection} <-
           apply_oidcc(opts, [TokenIntrospection], :introspect, [
             token,
             client_context,
             opts
           ]) do
      {:ok, introspection}
    else
      {:error, :introspection_not_supported} ->
        {:ok, nil}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_introspection(_opts, _token) do
    {:ok, nil}
  end
end
