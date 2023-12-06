defmodule UeberauthOidcc.Callback do
  @moduledoc """
  Support implementation of `c:Ueberauth.Strategy.handle_callback!/1`
  """

  alias UeberauthOidcc.Config
  import UeberauthOidcc.Helpers

  import Plug.Conn, only: [get_session: 2, delete_session: 2]

  import Ueberauth.Strategy.Helpers, only: [callback_url: 1]

  @doc """
  Support implementation of `c:Ueberauth.Strategy.handle_callback!/1`

  Takes options and the `Plug.Conn.t()`, and returns either an updated
  `Plug.Conn.t()`, a token and the userinfo claims, or an error (and the
  updated conn).

  See `UeberauthOidcc.Error.set_described_error/3` for help with rendering the
  error.
  """
  @spec handle_callback(UeberauthOidcc.Config.t(), Plug.Conn.t()) ::
          {:ok, Plug.Conn.t(), Oidcc.Token.t(), userinfo :: :oidcc_jwt_util.claims()}
          | {:error, Plug.Conn.t(), term}
  def handle_callback(opts, conn)

  def handle_callback(opts, %{params: %{"code" => code}} = conn) when is_binary(code) do
    opts = Map.merge(Config.default(), Map.new(opts))

    session = get_session(conn, opts.session_key) || %{}
    conn = delete_session(conn, opts.session_key)

    userinfo? = opts.userinfo

    nonce =
      case Map.fetch(session, :raw_nonce) do
        {:ok, raw_nonce} -> url_encode64(:crypto.hash(:sha512, raw_nonce))
        :error -> :any
      end

    retrieve_token_params =
      Map.merge(
        opts,
        %{
          nonce: nonce,
          pkce_verifier: Map.get(session, :pkce_verifier, :none),
          redirect_uri: callback_url(conn)
        }
      )

    maybe_token =
      with :ok <- validate_redirect_uri(Map.get(session, :redirect_uri, :any), conn),
           {:ok, token} <-
             apply_oidcc(opts, [], :retrieve_token, [
               code,
               opts.issuer,
               opts.client_id,
               opts.client_secret,
               retrieve_token_params
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

    with {:ok, token} <- maybe_token,
         :ok <-
           validate_token_scopes(token, Map.get(session, :scopes, :any), opts.validate_scopes),
         {:ok, userinfo} <- maybe_userinfo(opts, token) do
      {:ok, conn, token, userinfo}
    else
      {:error, reason} -> {:error, conn, reason}
    end
  end

  def handle_callback(opts, conn) do
    opts = Map.merge(Config.default(), Map.new(opts))
    conn = delete_session(conn, opts.session_key)

    {:error, conn, :missing_code}
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

  defp maybe_userinfo(%{userinfo: true} = opts, token) do
    provider_overrides = Map.take(opts, [:userinfo_endpoint])

    with {:ok, client_context} <- client_context(opts, provider_overrides) do
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
end
