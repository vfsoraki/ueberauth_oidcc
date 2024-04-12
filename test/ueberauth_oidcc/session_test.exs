defmodule UeberauthOidcc.SessionTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Plug.Test

  alias UeberauthOidcc.Session

  @default_opts Map.merge(
                  UeberauthOidcc.Config.default(),
                  %{callback_path: "/"}
                )

  setup do
    conn =
      :get
      |> conn("/")
      |> fetch_cookies()
      |> Map.put(:secret_key_base, "secret base")

    {:ok, conn: conn}
  end

  describe "put/3" do
    test "writes an encrypted cookie", %{conn: conn} do
      conn = Session.put(conn, @default_opts, :session_value)

      assert %{
               # validated in `get/3` tests,
               value: _,
               max_age: 3600,
               secure: false,
               same_site: "Lax",
               http_only: true
             } = conn.resp_cookies[@default_opts.session_cookie]
    end

    test "writes a secure cookie if the request used HTTPS", %{conn: conn} do
      conn = %Plug.Conn{conn | scheme: :https}
      conn = Session.put(conn, @default_opts, :session_value)
      cookie_name = "__Secure-#{@default_opts.session_cookie}"

      assert %{
               secure: true,
               http_only: true
             } = conn.resp_cookies[cookie_name]
    end

    test "allows overriding cookies values in opts", %{conn: conn} do
      opts =
        Map.merge(@default_opts, %{
          session_cookie: "cookie",
          session_max_age: 30,
          session_same_site: "None"
        })

      conn = Session.put(conn, opts, :session_value)

      assert %{
               max_age: 30,
               same_site: "None"
             } = conn.resp_cookies[opts.session_cookie]
    end

    test "limits the cookie to the callback path if one is provided", %{conn: conn} do
      opts =
        Map.merge(@default_opts, %{
          callback_path: "/callback"
        })

      conn = Session.put(conn, opts, :session_value)

      assert %{
               path: "/callback"
             } = conn.resp_cookies[opts.session_cookie]
    end
  end

  describe "get/3" do
    test "returns an default value if the session is not present", %{conn: conn} do
      assert Session.get(conn, @default_opts) == %{}
      assert Session.get(conn, @default_opts, :default) == :default
    end

    test "returns the value set by put/3", %{conn: conn} do
      written_conn = Session.put(conn, @default_opts, :session)

      conn =
        :get
        |> conn("/")
        |> Map.put(:secret_key_base, conn.secret_key_base)
        |> recycle_cookies(written_conn)
        |> fetch_cookies()

      assert Session.get(conn, @default_opts) == :session
    end

    test "ignores sessions which do not decrypt properly", %{conn: conn} do
      written_conn = Session.put(conn, @default_opts, :session)

      conn =
        :get
        |> conn("/")
        |> Map.put(:secret_key_base, "different secret base")
        |> recycle_cookies(written_conn)
        |> fetch_cookies()

      assert Session.get(conn, @default_opts, :default) == :default
    end

    test "cannot read a session after delete/2", %{conn: conn} do
      written_conn = Session.put(conn, @default_opts, :session)

      deleted_conn =
        :get
        |> conn("/")
        |> Map.put(:secret_key_base, conn.secret_key_base)
        |> recycle_cookies(written_conn)
        |> fetch_cookies()
        |> Session.delete(@default_opts)

      conn =
        :get
        |> conn("/")
        |> Map.put(:secret_key_base, conn.secret_key_base)
        |> recycle_cookies(deleted_conn)
        |> fetch_cookies()

      assert Session.get(conn, @default_opts, :default) == :default
    end
  end
end
