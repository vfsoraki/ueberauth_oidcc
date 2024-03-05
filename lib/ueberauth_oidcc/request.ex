defmodule UeberauthOidcc.Request do
  @moduledoc """
  Support implementation of `c:Ueberauth.Strategy.handle_request!/1`
  """

  alias UeberauthOidcc.Config
  alias UeberauthOidcc.Session
  import UeberauthOidcc.Helpers

  import Ueberauth.Strategy.Helpers, only: [callback_path: 1, callback_url: 1, redirect!: 2]

  @doc """
  Support implementation of `c:Ueberauth.Strategy.handle_request!/1`

  Takes options and the `Plug.Conn.t()`, and returns either an updated
  `Plug.Conn.t()` redirected to the authentication endpoint, or an error
  (and the updated conn).

  See `UeberauthOidcc.Error.set_described_error/3` for help with rendering the
  error.
  """
  @spec handle_request(UeberauthOidcc.Config.t(), Plug.Conn.t()) ::
          {:ok, Plug.Conn.t()} | {:error, Plug.Conn.t(), term}
  def handle_request(opts, conn) do
    opts =
      Config.default()
      |> Map.merge(Map.new(opts))
      |> opts_with_refresh()
      |> opts_with_passthrough(conn)
      |> Map.put_new(:callback_path, callback_path(conn))
      |> Map.put_new(:redirect_uri, callback_url(conn))

    # State: 24 URL-safe bytes
    state = url_encode64(:crypto.strong_rand_bytes(16))

    # Nonce: stored as raw bytes, sent as an encoded SHA256 string. This is the
    # approach recommended by the spec:
    # https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes 32 random
    # bytes is the same size as the SHA256 output. This results in a
    # 43-character base64url-encoded nonce, which is the max for safe interoperability.
    raw_nonce = :crypto.strong_rand_bytes(32)

    # PKCE Verifier: a 43 - 128 character string from the alphabet [A-Z] / [a-z]
    # / [0-9] / "-" / "." / "_" / "~". The recommendation is to generate a
    # random sequence and then base64url-encode it.
    # https://datatracker.ietf.org/doc/html/rfc7636#page-8
    # 96 random bytes results in an encoded 128 byte verifier.
    pkce_verifier = url_encode64(:crypto.strong_rand_bytes(96))

    redirect_params = %{
      response_type: opts.response_type,
      redirect_uri: opts.redirect_uri,
      state: state,
      pkce_verifier: pkce_verifier,
      nonce: url_encode64(:crypto.hash(:sha256, raw_nonce)),
      scopes: opts.scopes
    }

    case create_redirect_url(opts, redirect_params) do
      {:ok, uri, response_mode} ->
        conn =
          conn
          |> Session.put(opts, %{
            issuer: opts.issuer,
            state: state,
            raw_nonce: raw_nonce,
            pkce_verifier: pkce_verifier,
            redirect_uri: opts.redirect_uri,
            scopes: opts.scopes,
            response_mode: response_mode
          })
          |> redirect!(IO.iodata_to_binary(uri))

        {:ok, conn}

      {:error, reason} ->
        {:error, conn, reason}
    end
  end

  defp create_redirect_url(opts, redirect_params) do
    redirect_params =
      case Map.fetch(opts, :authorization_params) do
        {:ok, additional} ->
          Map.put(redirect_params, :url_extension, to_url_extension(additional))

        :error ->
          redirect_params
      end

    provider_overrides = Map.take(opts, [:authorization_endpoint])

    with {:ok, client_context, opts} <- client_context(opts, provider_overrides),
         response_mode =
           response_mode(client_context.provider_configuration.response_modes_supported, opts),
         redirect_params = Map.put(redirect_params, :response_mode, response_mode),
         {:ok, uri} <-
           apply_oidcc(opts, [Authorization], :create_redirect_url, [
             client_context,
             Map.merge(opts, redirect_params)
           ]) do
      {:ok, uri, response_mode}
    end
  end

  defp opts_with_passthrough(%{authorization_params_passthrough: param_names} = opts, %Plug.Conn{
         params: params
       }) do
    passthrough_params =
      for key <- param_names,
          key = to_string(key),
          value <- List.wrap(Map.get(params, key)),
          into: %{} do
        {key, value}
      end

    existing_authorization_params = Map.get(opts, :authorization_params, %{})
    authorization_params = Map.merge(existing_authorization_params, passthrough_params)

    Map.put(opts, :authorization_params, authorization_params)
  end

  defp opts_with_passthrough(opts, _conn) do
    opts
  end

  defp to_url_extension(enum) do
    for {key, value} <- enum do
      key =
        case key do
          a when is_atom(a) -> Atom.to_string(a)
          b when is_binary(b) -> b
        end

      {key, value}
    end
  end

  defp response_mode(response_modes_supported, opts) do
    supports_post? = "POST" in Map.get(opts, :callback_methods, [])

    cond do
      supports_post? and "form_post.jwt" in response_modes_supported ->
        "form_post.jwt"

      "query.jwt" in response_modes_supported ->
        "query.jwt"

      "jwt" in response_modes_supported ->
        "jwt"

      supports_post? and "form_post" in response_modes_supported ->
        "form_post"

      true ->
        "query"
    end
  end
end
