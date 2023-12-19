defmodule UeberauthOidcc.Request do
  @moduledoc """
  Support implementation of `c:Ueberauth.Strategy.handle_request!/1`
  """

  alias UeberauthOidcc.Config
  import UeberauthOidcc.Helpers

  import Plug.Conn, only: [put_session: 3]

  import Ueberauth.Strategy.Helpers, only: [callback_url: 1, with_state_param: 2, redirect!: 2]

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
      |> Map.put_new(:redirect_uri, callback_url(conn))

    # Nonce: stored as raw bytes, sent as an encoded SHA512 string. This is the
    # approach recommended by the spec:
    # https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
    # 64 random bytes is the same size as the SHA512 output.
    raw_nonce = :crypto.strong_rand_bytes(64)

    # PKCE Verifier: a 43 - 128 character string from the alphabet [A-Z] / [a-z]
    # / [0-9] / "-" / "." / "_" / "~". The recommendation is to generate a
    # random sequence and then base64url-encode it.
    # https://datatracker.ietf.org/doc/html/rfc7636#page-8
    # 96 random bytes results in an encoded 128 byte verifier.
    pkce_verifier = url_encode64(:crypto.strong_rand_bytes(96))

    redirect_params = %{
      response_type: opts.response_type,
      redirect_uri: opts.redirect_uri,
      state: with_state_param([], conn)[:state],
      pkce_verifier: pkce_verifier,
      nonce: url_encode64(:crypto.hash(:sha512, raw_nonce)),
      scopes: opts.scopes
    }

    case create_redirect_url(opts, redirect_params) do
      {:ok, uri} ->
        conn =
          conn
          |> put_session(opts.session_key, %{
            raw_nonce: raw_nonce,
            pkce_verifier: pkce_verifier,
            redirect_uri: opts.redirect_uri,
            scopes: opts.scopes
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

    opts = Map.put(opts, :client_secret, :unauthenticated)
    provider_overrides = Map.take(opts, [:authorization_endpoint])

    with {:ok, client_context} <- client_context(opts, provider_overrides) do
      apply_oidcc(opts, [Authorization], :create_redirect_url, [client_context, redirect_params])
    end
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
end
