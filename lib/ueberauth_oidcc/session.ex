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

    Conn.put_resp_cookie(conn, opts.session_cookie, value, cookie_opts(opts))
  end

  @spec get(Conn.t(), Config.t(), default :: term()) :: term()
  def get(conn, opts, default \\ %{}) do
    with cookie when is_binary(cookie) <- conn.req_cookies[opts.session_cookie],
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
    Conn.delete_resp_cookie(conn, opts.session_cookie, cookie_opts(opts))
  end

  defp cookie_opts(opts) do
    cookie_opts = [
      max_age: opts.session_max_age,
      http_only: true
    ]

    case opts do
      %{callback_path: path} ->
        [path: path] ++ cookie_opts

      _ ->
        cookie_opts
    end
  end
end
