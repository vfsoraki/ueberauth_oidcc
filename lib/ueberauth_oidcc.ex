defmodule UeberauthOidcc do
  @moduledoc """
  Documentation for `UeberauthOidcc`.
  """

  import Plug.Conn, only: [get_session: 2, delete_session: 2, put_session: 3]

  import Ueberauth.Strategy.Helpers,
    only: [callback_url: 1, with_state_param: 2, redirect!: 2, set_errors!: 2, error: 2]

  @type opts :: %{
          required(:issuer) => atom,
          required(:client_id) => binary(),
          required(:client_secret) => binary(),
          optional(:module) => module(),
          optional(:response_type) => binary(),
          optional(:scopes) => :oidcc_scope.scopes(),
          optional(:validate_scopes) => boolean(),
          optional(:session_key) => binary(),
          optional(:authorization_params) => Enumerable.t(),
          optional(:authorization_endpoint) => binary(),
          optional(:redirect_uri) => binary(),
          optional(:userinfo) => boolean(),
          optional(:userinfo_endpoint) => binary()
        }

  @doc """
  """
  @spec default_options() :: map
  def default_options() do
    %{
      module: Oidcc,
      response_type: "code",
      scopes: ["openid"],
      userinfo: false,
      validate_scopes: false,
      session_key: "ueberauth_strategy_oidcc"
    }
  end

  @doc """
  """
  @spec handle_request(opts, Plug.Conn.t()) ::
          {:ok, Plug.Conn.t()} | {:error, Plug.Conn.t(), term}
  def handle_request(opts, conn) do
    opts =
      default_options()
      |> Map.merge(Map.new(opts))
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

  @doc """
  """
  @spec handle_callback(opts, Plug.Conn.t()) ::
          {:ok, Plug.Conn.t(), Oidcc.Token.t(), Oidcc.Userinfo} | {:error, Plug.Conn.t(), term}
  def handle_callback(opts, conn)

  def handle_callback(opts, %{params: %{"code" => code}} = conn) when is_binary(code) do
    opts = Map.merge(default_options(), Map.new(opts))

    session = get_session(conn, opts.session_key) || %{}
    conn = delete_session(conn, opts.session_key)

    userinfo? = opts.userinfo

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
          pkce_verifier: Map.get(session, :pkce_verifier, :none),
          redirect_uri: callback_url(conn)
        }
      )

    maybe_token =
      with :ok <- validate_redirect_uri(Map.get(session, :redirect_uri, :any), conn),
           {:ok, token} <-
             apply_oidcc(opts, :retrieve_token, [
               code,
               opts.issuer,
               opts.client_id,
               opts.client_secret,
               retrieve_token_params
             ]) do
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
         :ok <-
           validate_token_scopes(token, Map.get(session, :scopes, :any), opts.validate_scopes),
         {:ok, userinfo} <- maybe_userinfo(opts, token) do
      {:ok, conn, token, userinfo}
    else
      {:error, reason} -> {:error, conn, reason}
    end
  end

  def handle_callback(opts, conn) do
    opts = Map.merge(default_options(), Map.new(opts))
    conn = delete_session(conn, opts.session_key)

    {:error, conn, :missing_code}
  end

  def set_described_error(conn, reason, key \\ nil) do
    error =
      if key do
        describe_error(reason, key)
      else
        describe_error(reason)
      end

    set_errors!(conn, [error])
  end

  def describe_error(reason, key \\ "error")

  def describe_error(:missing_issuer, _key) do
    error("issuer", "Missing issuer")
  end

  def describe_error(:missing_client_id, _key) do
    error("client_id", "Missing client_id")
  end

  def describe_error(:missing_code, _key) do
    error("code", "Query string does not contain field 'code'")
  end

  def describe_error({:invalid_redirect_uri, uri}, _key) do
    error("redirect_uri", "Redirected to the wrong URI: #{uri}")
  end

  def describe_error({:additional_scopes, scopes}, _key) do
    error(
      "scope",
      "Unrequested scopes received: #{Enum.intersperse(scopes, " ")}"
    )
  end

  def describe_error({:http_error, _code, %{"error" => error} = body}, _key) do
    description = Map.get(body, "error_description", "")

    error(
      error,
      description
    )
  end

  def describe_error(reason, key) do
    error(key, inspect(reason))
  end

  def credentials(token) do
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

    %Ueberauth.Auth.Credentials{
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

  def info(token, userinfo \\ nil) do
    claims =
      Map.merge(
        token.id.claims,
        userinfo || %{}
      )

    urls =
      %{}
      |> add_optional_url(:profile, claims["profile"])
      |> add_optional_url(:website, claims["website"])

    # https://openid.net/specs/openid-connect-core-1_0.html#Claims
    %Ueberauth.Auth.Info{
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

  @doc """
  """
  def client_context(opts, provider_overrides \\ %{})

  def client_context(%{issuer: _, client_id: _, client_secret: _} = opts, provider_overrides) do
    with {:ok, client_context} <-
           apply_oidcc(opts, [ClientContext], :from_configuration_worker, [
             opts.issuer,
             opts.client_id,
             opts.client_secret,
             opts
           ]) do
      client_context = %{
        client_context
        | provider_configuration:
            Map.merge(client_context.provider_configuration, provider_overrides)
      }

      {:ok, client_context}
    end
  end

  def client_context(%{client_id: _, client_secret: _}, _overrides) do
    {:error, :missing_issuer}
  end

  def client_context(%{client_secret: _}, _overrides) do
    {:error, :missing_client_id}
  end

  def client_context(%{}, _overrides) do
    {:error, :missing_client_secret}
  end

  defp apply_oidcc(opts, additional_mods \\ [], fun, args) do
    mod = Module.concat([opts.module | additional_mods])
    apply(mod, fun, args)
  end

  @doc """
  """
  def merge_and_expand_configuration(configurations) do
    Enum.reduce(configurations, default_options(), &merge_and_expand_one_configuration/2)
  end

  defp merge_and_expand_one_configuration(config, opts) do
    new_opts =
      config
      |> Enum.flat_map(&expand_configuration/1)
      |> Map.new()

    Map.merge(opts, new_opts)
  end

  defp expand_configuration(key_value)

  defp expand_configuration({key, {:system, env_var}}) do
    case System.fetch_env(env_var) do
      {:ok, value} ->
        [{key, value}]

      :error ->
        # don't use the value if it's not defined
        []
    end
  end

  defp expand_configuration({key, {:system, env_var, default}}) do
    value = System.get_env(env_var) || default
    [{key, value}]
  end

  defp expand_configuration({key, {mod, fun, args}}) do
    [{key, apply(mod, fun, args)}]
  end

  defp expand_configuration({key, fun}) when is_function(fun, 0) do
    [{key, fun.()}]
  end

  defp expand_configuration({key, value}) do
    [{key, value}]
  end

  @doc """
  Create a logout URL for a given `t:Ueberauth.Auth.t/0` struct.

  Also takes a an map of query parameters to append to the URL.
  """
  @spec initiate_logout_url(
          auth :: Ueberauth.Auth.t(),
          opts :: :oidcc_logout.initiate_url_opts() | :oidcc_client_context.opts()
        ) :: {:ok, String.t()} | {:error, term()}
  def initiate_logout_url(auth, opts \\ %{})

  def initiate_logout_url(%Ueberauth.Auth{strategy: Ueberauth.Strategy.Oidcc} = auth, opts) do
    strategy_opts = auth.extra.raw_info.opts
    id_token = auth.credentials.other.id_token

    case strategy_opts.module.initiate_logout_url(
           id_token,
           strategy_opts.issuer,
           strategy_opts.client_id,
           opts
         ) do
      {:ok, iodata} -> {:ok, IO.iodata_to_binary(iodata)}
      other -> other
    end
  end

  def initiate_logout_url(%Ueberauth.Auth{} = auth, _params) do
    {:error, {:invalid_strategy, auth.strategy}}
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

  defp validate_token_scopes(_, :any, _) do
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

  defp maybe_userinfo(%{userinfo: true} = opts, token) do
    provider_overrides = Map.take(opts, [:userinfo_endpoint])

    with {:ok, client_context} <- client_context(opts, provider_overrides) do
      apply_oidcc(opts, [Userinfo], :retrieve, [
        token,
        client_context,
        opts
      ])
    end
  end

  defp maybe_userinfo(_opts, _token) do
    {:ok, nil}
  end

  defp url_encode64(bytes) do
    Base.url_encode64(bytes, padding: false)
  end

  defp add_optional_url(urls, field, value)
  defp add_optional_url(urls, _field, nil), do: urls
  defp add_optional_url(urls, field, value), do: Map.put(urls, field, value)
end
