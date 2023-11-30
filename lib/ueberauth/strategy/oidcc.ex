defmodule Ueberauth.Strategy.Oidcc do
  @moduledoc """
  OIDC Strategy for Ueberauth.
  """

  use Ueberauth.Strategy

  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Auth.Info

  @session_key "ueberauth_strategy_oidcc"

  @doc """
  Handles the initial authentication request.
  """
  def handle_request!(conn) do
    opts = get_options!(conn)

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

    redirect_params =
      [
        response_type: opts.response_type,
        redirect_uri: opts.redirect_uri,
        pkce_verifier: pkce_verifier,
        nonce: url_encode64(:crypto.hash(:sha512, raw_nonce)),
        scopes: opts.scopes
      ]
      |> with_state_param(conn)
      |> Map.new()

    maybe_uri =
      if authorization_endpoint = Map.get(opts, :authorization_endpoint) do
        redirect_params =
          redirect_params
          |> Map.put(:client_id, opts.client_id)
          |> Map.put(:scope, Enum.join(redirect_params.scopes, " "))
          |> Map.delete(:scopes)
          |> Map.merge(Map.get(opts, :authorization_params, %{}))

        query = URI.encode_query(redirect_params)
        {:ok, "#{authorization_endpoint}?#{query}"}
      else
        redirect_params =
          case Map.fetch(opts, :authorization_params) do
            {:ok, additional} ->
              Map.put(redirect_params, :url_extension, to_url_extension(additional))

            :error ->
              redirect_params
          end

        case opts do
          %{issuer: _, client_id: _} ->
            opts.module.create_redirect_url(
              opts.issuer,
              opts.client_id,
              :unauthenticated,
              redirect_params
            )

          %{client_id: _} ->
            {:error, :missing_issuer}

          %{} ->
            {:error, :missing_client_id}
        end
      end

    case maybe_uri do
      {:ok, uri} ->
        conn
        |> put_session(@session_key, %{
          raw_nonce: raw_nonce,
          pkce_verifier: pkce_verifier,
          redirect_uri: opts.redirect_uri
        })
        |> redirect!(IO.iodata_to_binary(uri))

      {:error, reason} ->
        set_error!(
          conn,
          "create_redirect_url",
          inspect(reason)
        )
    end
  end

  @doc """
  Handles the callback from the oidc provider.
  """
  def handle_callback!(%{params: %{"code" => code}} = conn) when is_binary(code) do
    session = get_session(conn, @session_key, %{})

    opts = get_options!(conn)

    conn =
      conn
      |> delete_session(@session_key)
      |> put_private(:ueberauth_oidcc_opts, opts)

    userinfo? = Map.get(opts, :userinfo, false)

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
          pkce_verifier: Map.get(session, :pkce_verifier, :none)
        }
      )

    maybe_token =
      with :ok <- validate_redirect_uri(Map.get(session, :redirect_uri, :any), conn),
           {:ok, token} <-
             opts.module.retrieve_token(
               code,
               opts.issuer,
               opts.client_id,
               opts.client_secret,
               retrieve_token_params
             ) do
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
         :ok <- validate_token_scopes(token, retrieve_token_params.scopes, opts.validate_scopes) do
      conn
      |> put_private(:ueberauth_oidcc_token, token)
      |> maybe_put_userinfo(userinfo?)
    else
      {:error, {:additional_scopes, scopes}} ->
        set_error!(
          conn,
          "retrieve_token",
          "Unrequested scopes received: #{Enum.intersperse(scopes, " ")}"
        )

      {:error, {:invalid_redirect_uri, uri}} ->
        set_error!(conn, "retrieve_token", "Redirected to the wrong URI: #{uri}")

      {:error, reason} ->
        set_error!(conn, "retrieve_token", inspect(reason))
    end
  end

  def handle_callback!(conn) do
    set_error!(conn, "code", "Query string does not contain field 'code'")
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

  defp maybe_put_userinfo(conn, true) do
    opts = conn.private.ueberauth_oidcc_opts

    case opts.module.retrieve_userinfo(
           conn.private.ueberauth_oidcc_token,
           opts.issuer,
           opts.client_id,
           opts.client_secret,
           opts
         ) do
      {:ok, userinfo} ->
        put_private(conn, :ueberauth_oidcc_userinfo, userinfo)

      {:error, reason} ->
        set_error!(conn, "retrieve_userinfo", inspect(reason))
    end
  end

  defp maybe_put_userinfo(conn, false) do
    conn
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:ueberauth_oidcc_opts, nil)
    |> put_private(:ueberauth_oidcc_token, nil)
    |> put_private(:ueberauth_oidcc_userinfo, nil)
  end

  @doc """
  Returns the configured uid field from the claims.
  """
  def uid(conn) do
    opts = conn.private.ueberauth_oidcc_opts
    uid_field = Map.get(opts, :uid_field, "sub")

    case conn.private do
      %{ueberauth_oidcc_userinfo: %{^uid_field => uid}} ->
        uid

      %{ueberauth_oidcc_token: token} ->
        Map.get(token.id.claims, uid_field)
    end
  end

  @doc """
  Returns the credentials from the oidc response.

  `other` includes `id_token`
  """
  def credentials(conn) do
    token = conn.private.ueberauth_oidcc_token

    refresh_token =
      case token.refresh do
        %{token: token} -> token
        _ -> nil
      end

    expires_at =
      case token.access.expires do
        e when is_integer(e) ->
          System.system_time(:second) + e

        _ ->
          nil
      end

    %Credentials{
      token: token.access.token,
      refresh_token: refresh_token,
      token_type: "Bearer",
      expires: !!token.access.expires,
      expires_at: expires_at,
      scopes: token.scope,
      other: %{
        id_token: token.id.token
      }
    }
  end

  @doc """
  Returns an `Ueberauth.Auth.Extra` struct containing the claims and userinfo response.
  """
  def extra(conn) do
    %Extra{
      raw_info: %UeberauthOidcc.RawInfo{
        opts: conn.private.ueberauth_oidcc_opts,
        claims: conn.private.ueberauth_oidcc_token.id.claims,
        userinfo: conn.private[:ueberauth_oidcc_userinfo]
      }
    }
  end

  @doc """
  Returns a `Ueberauth.Auth.Info` struct populated with the data returned from
  the userinfo endpoint.

  This information is also included in the `Ueberauth.Auth.Credentials` struct.
  """
  def info(conn) do
    userinfo = conn.private[:ueberauth_oidcc_userinfo] || %{}

    claims = Map.merge(conn.private.ueberauth_oidcc_token.id.claims, userinfo)

    urls =
      %{}
      |> add_optional_url(:profile, claims["profile"])
      |> add_optional_url(:website, claims["website"])

    # https://openid.net/specs/openid-connect-core-1_0.html#Claims
    %Info{
      name: claims["name"],
      first_name: claims["given_name"],
      last_name: claims["family_name"],
      nickname: claims["nickname"],
      email: claims["email"],
      # address claim is a JSON blob
      location: nil,
      description: nil,
      image: claims["picture"],
      phone: claims["phone_number"],
      birthday: claims["birthdate"],
      urls: urls
    }
  end

  defp set_error!(conn, key, message) when is_binary(key) and is_binary(message) do
    set_errors!(conn, [error(key, message)])
  end

  defp get_options!(conn) do
    defaults = %{
      module: Oidcc,
      redirect_uri: callback_url(conn),
      response_type: "code",
      scopes: ["openid"],
      validate_scopes: false
    }

    compile_opts = Map.new(options(conn))

    runtime_opts =
      Map.new(
        (Application.get_env(:ueberauth_oidcc, :strategies) || [])[strategy_name(conn)] || %{}
      )

    defaults
    |> Map.merge(compile_opts)
    |> Map.merge(runtime_opts)
  end

  defp add_optional_url(urls, field, value)
  defp add_optional_url(urls, _field, nil), do: urls
  defp add_optional_url(urls, field, value), do: Map.put(urls, field, value)

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

  defp url_encode64(bytes) do
    Base.url_encode64(bytes, padding: false)
  end
end
