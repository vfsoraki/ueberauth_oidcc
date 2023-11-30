defmodule Ueberauth.Strategy.OidccTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias Ueberauth.Strategy.Oidcc

  @default_options [
    module: FakeOidcc,
    issuer: :fake_issuer,
    client_id: "oidc_client",
    client_secret: "secret_value",
    scopes: ~w(openid profile)
  ]

  describe "Oidcc Strategy" do
    setup do
      {:ok, conn: init_test_session(conn(:get, "/auth/provider"), %{})}
    end

    test "Handles an Oidcc request", %{conn: conn} do
      conn = Ueberauth.run_request(conn, :provider, {Oidcc, @default_options})

      assert {302, _headers, _body} = sent_resp(conn)

      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, "#{FakeOidcc.request_url()}?")

      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "redirect_uri" => "http://www.example.com/auth/provider/callback",
               "client_id" => "oidc_client",
               "scope" => "openid profile",
               "response_type" => "code",
               "state" => _
             } = query
    end

    test "handle overriding configuration with application config", %{conn: conn} do
      Application.put_env(
        :ueberauth_oidcc,
        :strategies,
        override_provider: [
          scopes: ~w(openid override-scope)
        ]
      )

      conn = Ueberauth.run_request(conn, :override_provider, {Oidcc, @default_options})

      assert {302, _headers, _body} = sent_resp(conn)

      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "scope" => "openid override-scope"
             } = query
    end

    test "Handles an error in an Oidcc request", %{conn: conn} do
      options = Keyword.delete(@default_options, :issuer)
      conn = Ueberauth.run_request(conn, :provider, {Oidcc, options})
      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "create_redirect_url",
               message: :missing_issuer
             } = error
    end

    test "Handle callback from provider with a callback_path", %{conn: conn} do
      options = Keyword.put(@default_options, :callback_path, "/custom_callback")
      conn = Ueberauth.run_request(conn, :provider, {Oidcc, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)
      assert query["redirect_uri"] == "http://www.example.com/custom_callback"
    end

    test "Handle callback from provider with custom request scopes", %{conn: conn} do
      options = Keyword.put(@default_options, :scopes, ~w(openid custom))
      conn = Ueberauth.run_request(conn, :provider, {Oidcc, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "scope" => "openid custom"
             } = query
    end

    test "handle additional redirect parameters", %{conn: conn} do
      options =
        Keyword.put(@default_options, :authorization_params, %{"request" => "param&encoded"})

      conn = Ueberauth.run_request(conn, :provider, {Oidcc, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "request" => "param&encoded"
             } = query
    end

    test "handle overriden authorization_endpoint", %{conn: conn} do
      options =
        Keyword.put(
          @default_options,
          :authorization_endpoint,
          "https://oidc-override.example/request"
        )

      conn = Ueberauth.run_request(conn, :provider, {Oidcc, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, "https://oidc-override.example/request?")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "redirect_uri" => _,
               "client_id" => _,
               "scope" => _,
               "state" => _,
               "response_type" => _
             } = query
    end

    test "handle overriden authorization_endpoint and authorization_params", %{conn: conn} do
      options =
        Keyword.merge(@default_options,
          authorization_endpoint: "https://oidc-override.example/request",
          authorization_params: %{"request" => "param"}
        )

      conn = Ueberauth.run_request(conn, :provider, {Oidcc, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, "https://oidc-override.example/request?")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "redirect_uri" => _,
               "client_id" => _,
               "scope" => _,
               "state" => _,
               "response_type" => _,
               "request" => "param"
             } = query
    end

    test "Handle callback from Oidcc with default uid field (sub)", %{conn: conn} do
      conn = run_request_and_callback(conn)

      assert %Ueberauth.Auth{
               provider: :provider,
               strategy: Ueberauth.Strategy.Oidcc,
               uid: "sub_value",
               credentials: %Ueberauth.Auth.Credentials{
                 expires: true,
                 expires_at: _,
                 token: "access_token_value",
                 token_type: "Bearer",
                 refresh_token: "refresh_token_value",
                 other: %{id_token: "id_token_value"}
               },
               info: %Ueberauth.Auth.Info{email: "email_value"},
               extra: %Ueberauth.Auth.Extra{
                 raw_info: %{
                   claims: %{"sub" => _},
                   userinfo: nil
                 }
               }
             } = conn.assigns.ueberauth_auth

      assert conn.assigns.ueberauth_auth.credentials.expires_at > System.system_time(:second)

      assert conn.assigns.ueberauth_auth.credentials.expires_at <
               System.system_time(:second) + 600
    end

    test "handle callback when there's no user session", %{conn: conn} do
      conn = run_request_and_callback(conn, options: @default_options, session: %{})

      assert %Ueberauth.Auth{} = conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with an overriden uid field", %{conn: conn} do
      options = Keyword.put(@default_options, :uid_field, "email")
      conn = run_request_and_callback(conn, options: options)

      assert %Ueberauth.Auth{
               uid: "email_value"
             } = conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with an missing uid field", %{conn: conn} do
      options = Keyword.put(@default_options, :uid_field, "_missing_")
      conn = run_request_and_callback(conn, options: options)

      assert %Ueberauth.Auth{
               uid: nil
             } = conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with a userinfo endpoint and an overriden uid_field",
         %{conn: conn} do
      options =
        @default_options
        |> Keyword.put(:userinfo, true)
        |> Keyword.put(:uid_field, "email")

      conn = run_request_and_callback(conn, options: options)

      assert %Ueberauth.Auth{
               uid: "test@email.example",
               info: %Ueberauth.Auth.Info{
                 name: "Full Name",
                 first_name: "First",
                 last_name: "Last",
                 nickname: "Nickname",
                 email: "test@email.example",
                 image: "http://photo.example",
                 phone: "phone_number_value",
                 birthday: "1970-01-01",
                 urls: %{
                   profile: "http://profile.example",
                   website: "http://website.example"
                 }
               },
               extra: %Ueberauth.Auth.Extra{
                 raw_info: %{
                   userinfo: %{"sub" => "userinfo_sub"}
                 }
               }
             } = conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with a missing code", %{conn: conn} do
      conn = run_request_and_callback(conn, code: nil)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "code",
               message: "Query string does not contain field 'code'"
             } = error
    end

    test "Handle callback from provider with an invalid code", %{conn: conn} do
      conn = run_request_and_callback(conn, code: "invalid_code")

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "retrieve_token",
               message: :invalid_code
             } = error
    end

    test "Handle callback from provider with an invalid redirect_uri", %{conn: conn} do
      conn = run_request_and_callback(conn, callback_path: "/auth/invalid/callback")

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "retrieve_token",
               message: {:invalid_redirect_uri, "http://www.example.com/auth/invalid/callback"}
             } = error
    end

    test "Handle callback from provider who returns too many scopes", %{conn: conn} do
      options = Keyword.put(@default_options, :scopes, ~w(openid))

      conn = run_request_and_callback(conn, options: options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "retrieve_token",
               message: {:additional_scopes, ~w(profile)}
             } = error
    end

    test "Handle callback from provider with an error retrieving tokens", %{conn: conn} do
      options = Keyword.put(@default_options, :_retrieve_token, false)

      conn = run_request_and_callback(conn, options: options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "retrieve_token",
               message: :no_tokens
             } = error
    end

    test "Handle callback from provider when the ID token has an invalid nonce",
         %{conn: conn} do
      options = Keyword.put(@default_options, :_retrieve_token, :invalid_nonce)

      conn = run_request_and_callback(conn, options: options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "retrieve_token",
               message: {:missing_claim, {:nonce, _, _}}
             } = error
    end

    test "Handle callback from provider when the ID token is not signed and userinfo is not fetched",
         %{conn: conn} do
      options = Keyword.put(@default_options, :_retrieve_token, :alg_none)

      conn = run_request_and_callback(conn, options: options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "retrieve_token",
               message: _
             } = error
    end

    test "Handle callback from provider when the ID token is not signed and userinfo is fetched",
         %{conn: conn} do
      options =
        @default_options
        |> Keyword.put(:userinfo, true)
        |> Keyword.put(:_retrieve_token, :alg_none)

      conn = run_request_and_callback(conn, options: options)

      assert %Ueberauth.Auth{
               uid: "userinfo_sub"
             } = conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with an error fetching userinfo", %{conn: conn} do
      options =
        @default_options
        |> Keyword.put(:userinfo, true)
        |> Keyword.put(:_retrieve_userinfo, false)

      conn = run_request_and_callback(conn, options: options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "retrieve_userinfo",
               message: :no_userinfo
             } = error
    end

    test "Handle callback from provider when the ID token is not signed and there is an error fetching userinfo",
         %{conn: conn} do
      options =
        @default_options
        |> Keyword.put(:userinfo, true)
        |> Keyword.put(:_retrieve_token, :alg_none)
        |> Keyword.put(:_retrieve_userinfo, false)

      conn = run_request_and_callback(conn, options: options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "retrieve_userinfo",
               message: :no_userinfo
             } = error
    end

    test "handle cleanup of uberauth values in the conn" do
      conn_with_values = %Plug.Conn{
        private: %{
          ueberauth_oidcc_opts: :some_value,
          ueberauth_oidcc_token: :other_value,
          ueberauth_oidcc_userinfo: :different_value
        }
      }

      assert %Plug.Conn{
               private: %{
                 ueberauth_oidcc_opts: nil,
                 ueberauth_oidcc_token: nil,
                 ueberauth_oidcc_userinfo: nil
               }
             } = Oidcc.handle_cleanup!(conn_with_values)
    end
  end

  defp run_request_and_callback(conn, opts \\ []) do
    oidcc_options = Keyword.get(opts, :options, @default_options)
    conn_with_cookies = Ueberauth.run_request(conn, :provider, {Oidcc, oidcc_options})
    state_cookie = conn_with_cookies.resp_cookies["ueberauth.state_param"].value

    callback_path = Keyword.get(opts, :callback_path, "/auth/provider/callback")

    code_opt =
      case Keyword.fetch(opts, :code) do
        {:ok, nil} -> %{}
        {:ok, value} -> %{"code" => value}
        :error -> %{"code" => FakeOidcc.callback_code()}
      end

    session = Keyword.get_lazy(opts, :session, fn -> get_session(conn_with_cookies) end)

    conn =
      :get
      |> conn(
        callback_path,
        Map.merge(
          %{
            "state" => state_cookie
          },
          code_opt
        )
      )
      |> Map.put(:cookies, %{"ueberauth.state_param" => state_cookie})
      |> init_test_session(session)

    Ueberauth.run_callback(conn, :provider, {Oidcc, oidcc_options})
  end
end
