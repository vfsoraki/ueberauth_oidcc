defmodule UeberauthOidcc.Session do
  @moduledoc """
  Manages session information for an UeberauthOidcc request.
  """
  alias Plug.Conn
  alias UeberauthOidcc.Config

  @spec put(Conn.t(), Config.t(), term()) :: Conn.t()
  def put(conn, opts, session) do
    value =
      Plug.Crypto.encrypt(
        conn.secret_key_base,
        opts.session_key,
        session,
        max_age: opts.session_max_age
      )

    Conn.put_resp_cookie(
      conn,
      cookie_name(conn.scheme, opts.session_cookie),
      value,
      cookie_opts(conn.scheme, opts)
    )
  end

  @spec get(Conn.t(), Config.t(), default :: term()) :: term()
  def get(conn, opts, default \\ %{}) do
    with cookie when is_binary(cookie) <-
           conn.req_cookies[cookie_name(conn.scheme, opts.session_cookie)],
         {:ok, session} <-
           Plug.Crypto.decrypt(conn.secret_key_base, opts.session_key, cookie,
             max_age: opts.session_max_age
           ) do
      session
    else
      _ -> default
    end
  end

  def delete(conn, opts) do
    Conn.delete_resp_cookie(
      conn,
      cookie_name(conn.scheme, opts.session_cookie),
      cookie_opts(conn.scheme, opts)
    )
  end

  defp cookie_name(:https, session_cookie) do
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#attributes
    # > Cookies with names starting with __Secure- (dash is part of the prefix)
    # must be set with the secure flag from a secure page (HTTPS).
    "__Secure-" <> session_cookie
  end

  defp cookie_name(_conn, session_cookie) do
    session_cookie
  end

  defp cookie_opts(scheme, opts) do
    [
      path: opts.callback_path,
      max_age: opts.session_max_age,
      http_only: true,
      same_site: opts.session_same_site,
      secure: scheme == :https
    ]
  end
end
