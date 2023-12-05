defmodule Ueberauth.Strategy.Oidcc do
  @moduledoc """
  OIDC Strategy for Ueberauth.
  """
  use Ueberauth.Strategy

  import Ueberauth.Strategy.Helpers

  alias Ueberauth.Auth.Extra

  @doc """
  Handles the initial authentication request.
  """
  def handle_request!(conn) do
    opts = get_options!(conn)

    case UeberauthOidcc.handle_request(opts, conn) do
      {:ok, conn} ->
        conn

      {:error, conn, reason} ->
        UeberauthOidcc.set_described_error(conn, reason, "handle_request!")
    end
  end

  @doc """
  Handles the callback from the OIDC provider.
  """
  def handle_callback!(conn) do
    opts = get_options!(conn)

    conn = put_private(conn, :ueberauth_oidcc_opts, opts)

    case UeberauthOidcc.handle_callback(opts, conn) do
      {:ok, conn, token, userinfo} ->
        conn
        |> put_private(:ueberauth_oidcc_token, token)
        |> put_private(:ueberauth_oidcc_userinfo, userinfo)

      {:error, conn, reason} ->
        UeberauthOidcc.set_described_error(conn, reason, "handle_callback!")
    end
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
    UeberauthOidcc.credentials(token)
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
    UeberauthOidcc.info(
      conn.private.ueberauth_oidcc_token,
      conn.private[:ueberauth_oidcc_userinfo]
    )
  end

  defp get_options!(conn) do
    compile_opts = options(conn)

    runtime_opts =
      (Application.get_env(:ueberauth_oidcc, :providers) || [])[strategy_name(conn)] || []

    UeberauthOidcc.merge_and_expand_configuration([
      default_options(),
      compile_opts,
      runtime_opts
    ])
  end
end
