defmodule Ueberauth.Strategy.Oidcc do
  @moduledoc """
  OIDC Strategy for Ueberauth.
  """

  use Ueberauth.Strategy

  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Auth.Info

  @doc """
  Handles the initial authentication request.
  """
  def handle_request!(conn) do
    opts = get_options!(conn)

    params =
      params_from_conn(conn, %{
        response_type: opts.response_type,
        redirect_uri: opts.redirect_uri,
        scopes: opts.scopes
      })

    maybe_uri =
      if authorization_endpoint = Map.get(opts, :authorization_endpoint) do
        params =
          params
          |> Map.put(:client_id, opts.client_id)
          |> Map.put(:scope, Enum.join(params.scopes, " "))
          |> Map.delete(:scopes)
          |> Map.merge(Map.get(opts, :authorization_params, %{}))

        query = URI.encode_query(params)
        {:ok, "#{authorization_endpoint}?#{query}"}
      else
        params =
          if redirect_params = Map.get(opts, :authorization_params) do
            Map.put(params, :url_extension, to_url_extension(redirect_params))
          else
            params
          end

        case opts do
          %{issuer: _, client_id: _} ->
            opts.module.create_redirect_url(opts.issuer, opts.client_id, :unauthenticated, params)

          %{client_id: _} ->
            {:error, :missing_issuer}

          %{} ->
            {:error, :missing_client_id}
        end
      end

    case maybe_uri do
      {:ok, uri} ->
        redirect!(conn, IO.iodata_to_binary(uri))

      {:error, reason} ->
        set_error!(
          conn,
          "create_redirect_url",
          reason
        )
    end
  end

  @doc """
  Handles the callback from the oidc provider.
  """
  def handle_callback!(%{params: %{"code" => code}} = conn) when is_binary(code) do
    opts = get_options!(conn)
    conn = put_private(conn, :ueberauth_oidcc_opts, opts)
    userinfo? = Map.get(opts, :userinfo, false)

    maybe_token =
      case opts.module.retrieve_token(code, opts.issuer, opts.client_id, opts.client_secret, opts) do
        {:ok, %{id: %{claims: %{"nonce" => _}}}} ->
          # we don't provide a nonce, so a reply with a nonce is invalid
          # (oidcc-client-test-nonce-invalid)
          {:error, :invalid_nonce}

        {:ok, token} ->
          {:ok, token}

        {:error, {:none_alg_used, token}} when userinfo? ->
          # the none algorithm is okay for the ID token if we then verify the
          # userinfo (oidcc-client-test-idtoken-sig-none)
          {:ok, token}

        {:error, reason} ->
          {:error, reason}
      end

    case maybe_token do
      {:ok, token} ->
        conn
        |> put_private(:ueberauth_oidcc_token, token)
        |> maybe_put_userinfo(userinfo?)

      {:error, reason} ->
        set_error!(conn, "retrieve_token", reason)
    end
  end

  def handle_callback!(conn) do
    set_error!(conn, "code", "Query string does not contain field 'code'")
  end

  defp params_from_conn(conn, params) do
    []
    |> with_state_param(conn)
    |> Map.new()
    |> Map.merge(params)
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
        set_error!(conn, "retrieve_userinfo", reason)
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

  defp set_error!(conn, key, message) do
    set_errors!(conn, [error(key, message)])
  end

  defp get_options!(conn) do
    defaults = %{
      module: Oidcc,
      redirect_uri: callback_url(conn),
      response_type: "code",
      scopes: ["openid"]
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
end
