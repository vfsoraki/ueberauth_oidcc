defmodule Ueberauth.Strategy.OidccTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias Ueberauth.Strategy.Oidcc, as: Strategy
  alias UeberauthOidcc.Config
  alias UeberauthOidcc.Session

  @default_options [
    module: FakeOidcc,
    issuer: :fake_issuer,
    client_id: "oidc_client",
    client_secret: "secret_value",
    scopes: ~w(openid email)
  ]

  Code.ensure_loaded(Oidcc.Token)

  describe "Oidcc Strategy" do
    setup do
      conn = init_test_session(conn(:get, "/auth/provider"), %{})

      conn =
        Map.update!(conn, :secret_key_base, fn base ->
          if is_binary(base) do
            base
          else
            :crypto.strong_rand_bytes(32)
          end
        end)

      {:ok, conn: conn}
    end

    test "Handles an Oidcc request", %{conn: conn} do
      conn = Ueberauth.run_request(conn, :provider, {Strategy, @default_options})

      assert %{halted: true} = conn
      assert {302, _headers, _body} = sent_resp(conn)

      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, "#{FakeOidcc.request_url()}?")

      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "redirect_uri" => "http://www.example.com/auth/provider/callback",
               "client_id" => "oidc_client",
               "scope" => "openid email",
               "response_type" => "code",
               "state" => _
             } = query
    end

    test "Oidcc requests use `form_post` if POST is a supported callback method", %{conn: conn} do
      options =
        Keyword.merge(
          @default_options,
          callback_methods: ["POST"]
        )

      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})

      assert %{halted: true} = conn
      assert {302, _headers, _body} = sent_resp(conn)

      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, "#{FakeOidcc.request_url()}?")

      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "response_mode" => "form_post"
             } = query
    end

    test "Oidcc requests use `jwt` if supported", %{conn: conn} do
      options =
        Keyword.merge(
          @default_options,
          issuer: :fake_issuer_with_jwt
        )

      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})

      assert %{halted: true} = conn
      assert {302, _headers, _body} = sent_resp(conn)

      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, "#{FakeOidcc.request_url()}?")

      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "response_mode" => "jwt"
             } = query
    end

    test "Oidcc requests use `form_post.jwt` if supported and callback_methods include POST", %{
      conn: conn
    } do
      options =
        Keyword.merge(
          @default_options,
          issuer: :fake_issuer_with_jwt,
          callback_methods: ["POST"]
        )

      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})

      assert %{halted: true} = conn
      assert {302, _headers, _body} = sent_resp(conn)

      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, "#{FakeOidcc.request_url()}?")

      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "response_mode" => "form_post.jwt"
             } = query
    end

    test "handle overriding configuration with application config", %{conn: conn} do
      Application.put_env(
        :ueberauth_oidcc,
        :providers,
        override_provider: [
          scopes: ~w(openid override-scope)
        ]
      )

      conn = Ueberauth.run_request(conn, :override_provider, {Strategy, @default_options})

      assert {302, _headers, _body} = sent_resp(conn)

      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "scope" => "openid override-scope"
             } = query
    end

    test "can pass through query parameters if specified", %{conn: conn} do
      options = Keyword.put(@default_options, :authorization_params_passthrough, ~w(prompt))
      conn = %{conn | params: %{"prompt" => "login", "additional" => "ignored"}}
      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})

      assert {302, _headers, _body} = sent_resp(conn)

      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "prompt" => "login"
             } = query

      refute Map.has_key?(query, "additional")
    end

    test "pass through parameters override specified parameters", %{conn: conn} do
      options =
        Keyword.merge(@default_options,
          authorization_params_passthrough: ~w(prompt),
          authorization_params: %{prompt: "login", kept: "value"}
        )

      conn = %{conn | params: %{"prompt" => "create"}}
      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})

      assert {302, _headers, _body} = sent_resp(conn)

      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "prompt" => "create",
               "kept" => "value"
             } = query
    end

    test "Handles an error in an Oidcc request (invalid issuer)", %{conn: conn} do
      options = Keyword.merge(@default_options, issuer: :not_valid)
      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})
      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "handle_request!",
               message: ":not_defined"
             } = error
    end

    test "Handles an error in an Oidcc request (missing issuer)", %{conn: conn} do
      options = Keyword.delete(@default_options, :issuer)
      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})
      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "config",
               message: "Missing issuer"
             } = error
    end

    test "Handles an error in an Oidcc request (missing client_id)", %{conn: conn} do
      options = Keyword.delete(@default_options, :client_id)
      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})
      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "config",
               message: "Missing client_id"
             } = error
    end

    test "Handle callback from provider with a callback_path", %{conn: conn} do
      options = Keyword.put(@default_options, :callback_path, "/custom_callback")
      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)
      assert query["redirect_uri"] == "http://www.example.com/custom_callback"
    end

    test "Handle callback from provider with custom request scopes", %{conn: conn} do
      options = Keyword.put(@default_options, :scopes, ~w(openid custom))
      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "scope" => "openid custom"
             } = query
    end

    test "handle additional redirect parameters", %{conn: conn} do
      options =
        Keyword.put(@default_options, :authorization_params, %{
          "request" => "param&encoded",
          atom: "value"
        })

      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})

      assert {302, _headers, _body} = sent_resp(conn)
      [location] = get_resp_header(conn, "location")
      query = URI.decode_query(URI.parse(location).query)

      assert %{
               "request" => "param&encoded",
               "atom" => "value"
             } = query
    end

    test "handle overriden authorization_endpoint", %{conn: conn} do
      options =
        Keyword.put(
          @default_options,
          :authorization_endpoint,
          "https://oidc-override.example/request"
        )

      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})

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

      conn = Ueberauth.run_request(conn, :provider, {Strategy, options})

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
      {request_conn, conn} = run_request_and_callback(conn, return_request_conn: true)

      [redirect_location] = get_resp_header(request_conn, "location")
      %{"nonce" => nonce} = URI.decode_query(URI.parse(redirect_location).query)

      assert %Ueberauth.Auth{
               provider: :provider,
               strategy: Strategy,
               uid: "sub_value",
               credentials: %Ueberauth.Auth.Credentials{
                 expires: true,
                 expires_at: _,
                 token: "access_token_value",
                 token_type: "Bearer",
                 refresh_token: nil,
                 other: %{id_token: "id_token_value"}
               },
               info: %Ueberauth.Auth.Info{email: "email_value"},
               extra: %Ueberauth.Auth.Extra{
                 raw_info: %{
                   claims: %{"sub" => _, "nonce" => ^nonce},
                   userinfo: nil
                 }
               }
             } = conn.assigns.ueberauth_auth

      assert conn.assigns.ueberauth_auth.credentials.expires_at > System.system_time(:second)

      assert conn.assigns.ueberauth_auth.credentials.expires_at <
               System.system_time(:second) + 600
    end

    test "Handle callback with a refresh token (offline_access scope)", %{conn: conn} do
      options =
        Keyword.merge(@default_options,
          scopes: ~w(openid offline_access)
        )

      conn = run_request_and_callback(conn, options: options)

      assert %Ueberauth.Auth{
               credentials: %Ueberauth.Auth.Credentials{
                 refresh_token: "refresh_token_value"
               }
             } = conn.assigns.ueberauth_auth
    end

    test "Handle callback with a non-expiring access token", %{conn: conn} do
      options = Keyword.put(@default_options, :_access_token_expires, nil)

      conn = run_request_and_callback(conn, options: options)

      assert %Ueberauth.Auth{
               credentials: %Ueberauth.Auth.Credentials{
                 expires_at: nil
               }
             } = conn.assigns.ueberauth_auth
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

    test "Handle callback from provider with a token introspection endpoint",
         %{conn: conn} do
      options =
        @default_options
        |> Keyword.put(:introspection, true)

      conn = run_request_and_callback(conn, options: options)

      assert %Ueberauth.Auth{
               extra: %Ueberauth.Auth.Extra{
                 raw_info: %{
                   introspection: %Oidcc.TokenIntrospection{
                     active: true
                   }
                 }
               }
             } = conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with a token introspection endpoint even if introspection is not supported",
         %{conn: conn} do
      options =
        @default_options
        |> Keyword.put(:introspection, true)
        |> Keyword.put(:_introspect, :not_supported)

      conn = run_request_and_callback(conn, options: options)

      assert %Ueberauth.Auth{
               extra: %Ueberauth.Auth.Extra{
                 raw_info: %{
                   introspection: nil
                 }
               }
             } = conn.assigns.ueberauth_auth
    end

    test "Handle callback clears the session cookie", %{conn: conn} do
      {request_conn, conn} = run_request_and_callback(conn, return_request_conn: true)
      cookie = "_ueberauth_strategy_oidcc"
      refute Map.has_key?(conn.resp_cookies[cookie], :value)

      request_keys = Map.keys(request_conn.resp_cookies[cookie]) -- [:value]
      cleared_keys = Map.keys(conn.resp_cookies[cookie]) -- [:universal_time]
      # make sure we're setting all the same cookie parameters when clearing
      assert request_keys == cleared_keys
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
               message_key: "handle_callback!",
               message: ":invalid_code"
             } = error
    end

    test "Handle callback from provider with a valid JARM response", %{conn: conn} do
      options = Keyword.put(@default_options, :issuer, :fake_issuer_with_jwt)
      conn = run_request_and_callback(conn, options: options, code: {:jarm, "jarm_response"})

      assert %Ueberauth.Auth{} = conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with a valid JARM error", %{conn: conn} do
      options = Keyword.put(@default_options, :issuer, :fake_issuer_with_jwt)
      conn = run_request_and_callback(conn, options: options, code: {:jarm, "jarm_error"})

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "access_denied",
               message: "authentication_expired"
             } = error
    end

    test "Handle callback from provider with an invalid JARM response", %{conn: conn} do
      options = Keyword.put(@default_options, :issuer, :fake_issuer_with_jwt)
      conn = run_request_and_callback(conn, options: options, code: {:jarm, "invalid_response"})

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "handle_callback!",
               message: ":token_expired"
             } = error
    end

    test "Handle callback from provider with an invalid state", %{conn: conn} do
      conn = run_request_and_callback(conn, state_suffix: "1")

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "csrf_attack",
               message: "Cross-Site Request Forgery attack"
             } = error
    end

    test "Handle callback from provider with an invalid redirect_uri", %{conn: conn} do
      conn = run_request_and_callback(conn, callback_path: "/auth/invalid/callback")

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "redirect_uri",
               message:
                 "Redirected to the wrong URI: http://www.example.com/auth/invalid/callback"
             } = error
    end

    test "Handle callback from provider who returns too many scopes", %{conn: conn} do
      options =
        Keyword.merge(@default_options,
          scopes: ~w(openid),
          validate_scopes: true
        )

      conn = run_request_and_callback(conn, options: options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "scope",
               message: "Unrequested scopes received: profile"
             } = error
    end

    test "Handle callback from provider with an error retrieving tokens", %{conn: conn} do
      options = Keyword.put(@default_options, :_retrieve_token, false)

      conn = run_request_and_callback(conn, options: options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "handle_callback!",
               message: ":no_tokens"
             } = error
    end

    test "Handle callback from provider when the ID token has an invalid nonce",
         %{conn: conn} do
      options = Keyword.put(@default_options, :_retrieve_token, :invalid_nonce)

      conn = run_request_and_callback(conn, options: options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "handle_callback!"
             } = error

      assert error.message =~ ":missing_claim, {:nonce"
    end

    test "Handle callback from provider when the ID token is not signed and userinfo is not fetched",
         %{conn: conn} do
      options = Keyword.put(@default_options, :_retrieve_token, :alg_none)

      conn = run_request_and_callback(conn, options: options)

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "handle_callback!",
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
               message_key: "handle_callback!",
               message: ":no_userinfo"
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
               message_key: "handle_callback!",
               message: ":no_userinfo"
             } = error
    end

    test "Handle callback from provider with a valid iss param",
         %{conn: conn} do
      conn = run_request_and_callback(conn, url_params: %{"iss" => "https://issuer.example"})

      assert conn.assigns.ueberauth_auth
    end

    test "Handle callback from provider with an invalid iss param",
         %{conn: conn} do
      conn =
        run_request_and_callback(conn,
          url_params: %{"iss" => "https://issuer.example/invalid"}
        )

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "issuer",
               message:
                 "Expected code for issuer https://issuer.example, but got callback for https://issuer.example/invalid"
             } = error
    end

    test "Handle callback from provider with a missing iss param when it's expected",
         %{conn: conn} do
      options = Keyword.put(@default_options, :issuer, :fake_issuer_with_iss)

      conn =
        run_request_and_callback(conn,
          options: options
        )

      [error | _] = conn.assigns.ueberauth_failure.errors

      assert %Ueberauth.Failure.Error{
               message_key: "iss",
               message: "Missing expected iss param"
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
             } = Strategy.handle_cleanup!(conn_with_values)
    end
  end

  defp run_request_and_callback(conn, opts) do
    oidcc_options = Keyword.get(opts, :options, @default_options)
    conn_with_cookies = Ueberauth.run_request(conn, :provider, {Strategy, oidcc_options})

    req_cookies =
      Map.new(conn_with_cookies.resp_cookies, fn {k, v} ->
        {k, v.value}
      end)

    session =
      Session.get(
        %{conn_with_cookies | req_cookies: req_cookies},
        Map.merge(Config.default(), Map.new(oidcc_options))
      )

    state = session.state <> Keyword.get(opts, :state_suffix, "")
    callback_path = Keyword.get(opts, :callback_path, "/auth/provider/callback")

    code_opt =
      case Keyword.fetch(opts, :code) do
        {:ok, nil} -> %{}
        {:ok, {:jarm, response}} -> %{"response" => response <> state}
        {:ok, value} -> %{"code" => value}
        :error -> %{"code" => FakeOidcc.callback_code()}
      end

    other_params = Keyword.get(opts, :url_params, %{})

    params =
      code_opt
      |> Map.put("state", state)
      |> Map.merge(other_params)

    conn =
      :get
      |> conn(callback_path, params)
      |> Map.put(:secret_key_base, conn_with_cookies.secret_key_base)
      |> Map.put(:req_cookies, req_cookies)
      |> Ueberauth.run_callback(:provider, {Strategy, oidcc_options})

    if opts[:return_request_conn] do
      {conn_with_cookies, conn}
    else
      conn
    end
  end
end
