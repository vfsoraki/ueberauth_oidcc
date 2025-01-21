defmodule FakeOidcc do
  # coveralls-ignore-start
  @moduledoc false

  def request_url do
    "https://oidc.example/request"
  end

  def callback_code do
    "valid_code"
  end

  # functions copied from the documentation: https://hexdocs.pm/oidcc/Oidcc.html

  def client_credentials_token(provider_configuration_name, client_id, client_secret, opts)

  def client_credentials_token(_, _, _, _) do
    {:error, :not_defined}
  end

  def create_redirect_url(provider_configuration_name, client_id, client_secret, opts) do
    with {:ok, context} <-
           __MODULE__.ClientContext.from_configuration_worker(
             provider_configuration_name,
             client_id,
             client_secret,
             opts
           ) do
      __MODULE__.Authorization.create_redirect_url(context, opts)
    end
  end

  def initiate_logout_url(token, provider_configuration_name, client_id, opts \\ %{})

  def initiate_logout_url("id_token_value" = id_token, :fake_issuer, "oidc_client" = client, opts) do
    query =
      Map.merge(
        %{
          client_id: client,
          id_token_hint: id_token
        },
        opts
      )

    {:ok, ["https://oidc.example/logout", "?", URI.encode_query(query)]}
  end

  def initiate_logout_url(_, _, _, _) do
    {:error, :not_defined}
  end

  def introspect_token(token, provider_configuration_name, client_id, client_secret, opts \\ %{})

  def introspect_token(_, _, _, _, _) do
    {:error, :not_defined}
  end

  def jwt_profile_token(subject, provider_configuration_name, client_id, client_secret, jwk, opts)

  def jwt_profile_token(_, _, _, _, _, _) do
    {:error, :not_defined}
  end

  def refresh_token(token, provider_configuration_name, client_id, client_secret, opts \\ %{})

  def refresh_token(_, _, _, _, _) do
    {:error, :not_defined}
  end

  def retrieve_token(code, provider_configuration_name, client_id, client_secret, opts) do
    with {:ok, context} <-
           __MODULE__.ClientContext.from_configuration_worker(
             provider_configuration_name,
             client_id,
             client_secret,
             opts
           ) do
      __MODULE__.Token.retrieve(code, context, opts)
    end

    {:error, :not_defined}
  end

  def retrieve_userinfo(token, provider_configuration_name, client_id, client_secret, opts \\ %{}) do
    with {:ok, context} <-
           __MODULE__.ClientContext.from_configuration_worker(
             provider_configuration_name,
             client_id,
             client_secret,
             opts
           ) do
      __MODULE__.Userinfo.retrieve(token, context, opts)
    end
  end

  defmodule ClientContext do
    @moduledoc false
    def from_configuration_worker(issuer, client_id, client_secret, opts)

    def from_configuration_worker(:fake_issuer, client_id, client_secret, _opts) do
      {:ok,
       Oidcc.ClientContext.from_manual(
         %Oidcc.ProviderConfiguration{
           issuer: "https://issuer.example",
           authorization_endpoint: FakeOidcc.request_url(),
           response_modes_supported: ["query", "fragment", "form_post"]
         },
         JOSE.JWK.generate_key({:oct, 8}),
         client_id,
         client_secret
       )}
    end

    def from_configuration_worker(:fake_issuer_with_iss, client_id, client_secret, _opts) do
      %Oidcc.ClientContext{
        provider_configuration: provider_configuration
      } =
        client_context =
        Oidcc.ClientContext.from_manual(
          %Oidcc.ProviderConfiguration{
            issuer: "https://issuer.example",
            authorization_endpoint: FakeOidcc.request_url(),
            authorization_response_iss_parameter_supported: true
          },
          JOSE.JWK.generate_key({:oct, 8}),
          client_id,
          client_secret
        )

      {:ok, %{client_context | provider_configuration: provider_configuration}}
    end

    def from_configuration_worker(:fake_issuer_with_jwt, client_id, client_secret, _opts) do
      %Oidcc.ClientContext{
        provider_configuration: provider_configuration
      } =
        client_context =
        Oidcc.ClientContext.from_manual(
          %Oidcc.ProviderConfiguration{
            issuer: "https://issuer.example",
            authorization_endpoint: FakeOidcc.request_url(),
            response_modes_supported: ["query", "jwt", "form_post.jwt"]
          },
          JOSE.JWK.generate_key({:oct, 8}),
          client_id,
          client_secret
        )

      {:ok, %{client_context | provider_configuration: provider_configuration}}
    end

    def from_configuration_worker(_, _, _, _) do
      {:error, :not_defined}
    end
  end

  defmodule Authorization do
    @moduledoc false
    def create_redirect_url(context, opts)

    def create_redirect_url(
          %Oidcc.ClientContext{
            client_id: "oidc_client" = client_id,
            client_secret: "secret_value",
            provider_configuration: %Oidcc.ProviderConfiguration{
              issuer: "https://issuer.example",
              authorization_endpoint: endpoint
            }
          },
          opts
        ) do
      params = %{
        client_id: client_id,
        redirect_uri: opts[:redirect_uri],
        state: opts[:state],
        nonce: opts[:nonce],
        response_type: opts[:response_type],
        scope: Enum.join(Map.get(opts, :scopes, []), " ")
      }

      params =
        case Map.get(opts, :response_mode, "query") do
          "query" ->
            params

          response_mode ->
            Map.put(params, :response_mode, response_mode)
        end

      extension =
        case Map.fetch(opts, :url_extension) do
          {:ok, e} -> ["&", URI.encode_query(e)]
          :error -> []
        end

      query = URI.encode_query(params)

      {:ok, [endpoint, "?", query, extension]}
    end

    def create_redirect_url(_, _) do
      {:error, :not_defined}
    end
  end

  defmodule Token do
    @moduledoc false
    def retrieve(code, context, opts) do
      retrieve_token(
        code,
        context.provider_configuration.issuer,
        context.client_id,
        context.client_secret,
        opts
      )
    end

    def retrieve_token(auth_code, issuer, client_id, client_secret, opts)

    def retrieve_token(_, _, _, _, %{:_retrieve_token => false}) do
      {:error, :no_tokens}
    end

    def retrieve_token(
          auth_code,
          issuer,
          client_id,
          client_secret,
          %{:_retrieve_token => :alg_none} = opts
        ) do
      opts = Map.delete(opts, :_retrieve_token)

      case retrieve_token(auth_code, issuer, client_id, client_secret, opts) do
        {:ok, token} ->
          {:error, {:none_alg_used, token}}

        {:error, _} = e ->
          e
      end
    end

    def retrieve_token(
          auth_code,
          issuer,
          client_id,
          client_secret,
          %{:_retrieve_token => :invalid_nonce} = opts
        ) do
      opts = Map.delete(opts, :_retrieve_token)

      case retrieve_token(auth_code, issuer, client_id, client_secret, opts) do
        {:ok, %{id: %{claims: claims}}} ->
          {:error, {:missing_claim, {:nonce, Map.get(opts, :nonce), claims}}}

        {:error, _} = e ->
          e
      end
    end

    def retrieve_token(
          auth_code,
          "https://issuer.example",
          "oidc_client",
          "secret_value",
          %{refresh_jwks: _} = opts
        ) do
      if auth_code == FakeOidcc.callback_code() do
        claims = %{
          "sub" => "sub_value",
          "email" => "email_value"
        }

        claims =
          case Map.get(opts, :nonce) do
            b when is_binary(b) -> Map.put(claims, "nonce", b)
            _ -> claims
          end

        refresh =
          if "offline_access" in opts.scopes do
            %Oidcc.Token.Refresh{
              token: "refresh_token_value"
            }
          else
            nil
          end

        token = %Oidcc.Token{
          access: %Oidcc.Token.Access{
            token: "access_token_value",
            # 5 minutes
            expires: Map.get(opts, :_access_token_expires, 300)
          },
          id: %Oidcc.Token.Id{
            token: "id_token_value",
            claims: claims
          },
          refresh: refresh,
          scope: ["openid", "profile"]
        }

        {:ok, token}
      else
        {:error, :invalid_code}
      end
    end

    def validate_jarm(
          "jarm_response" <> state,
          %Oidcc.ClientContext{
            client_id: "oidc_client",
            provider_configuration: %Oidcc.ProviderConfiguration{issuer: "https://issuer.example"}
          },
          _opts
        ) do
      {:ok, %{"code" => FakeOidcc.callback_code(), "state" => state}}
    end

    def validate_jarm(
          "jarm_error" <> state,
          %Oidcc.ClientContext{
            client_id: "oidc_client",
            provider_configuration: %Oidcc.ProviderConfiguration{issuer: "https://issuer.example"}
          },
          _opts
        ) do
      {:ok,
       %{
         "error" => "access_denied",
         "error_description" => "authentication_expired",
         "state" => state
       }}
    end

    def validate_jarm(_response, _client_context, _opts) do
      {:error, :token_expired}
    end
  end

  defmodule Userinfo do
    @moduledoc false
    def retrieve(token, context, opts)

    def retrieve(_, _, %{:_retrieve_userinfo => false}) do
      {:error, :no_userinfo}
    end

    def retrieve(
          %Oidcc.Token{access: %Oidcc.Token.Access{token: "access_token_value"}},
          %Oidcc.ClientContext{
            provider_configuration: %Oidcc.ProviderConfiguration{issuer: "https://issuer.example"},
            client_id: "oidc_client",
            client_secret: "secret_value"
          },
          %{refresh_jwks: _} = _opts
        ) do
      {:ok,
       %{
         "sub" => "userinfo_sub",
         "name" => "Full Name",
         "given_name" => "First",
         "family_name" => "Last",
         "nickname" => "Nickname",
         "email" => "test@email.example",
         "picture" => "http://photo.example",
         "phone_number" => "phone_number_value",
         "birthdate" => "1970-01-01",
         "profile" => "http://profile.example",
         "website" => "http://website.example"
       }}
    end

    def retrieve(_, _, _) do
      {:error, :not_defined}
    end
  end

  defmodule TokenIntrospection do
    @moduledoc false
    def introspect(token, context, opts)

    def introspect(_, _, %{:_introspect => :not_supported}) do
      {:error, :introspection_not_supported}
    end

    def introspect(
          %Oidcc.Token{access: %Oidcc.Token.Access{token: "access_token_value"}},
          %Oidcc.ClientContext{
            provider_configuration: %Oidcc.ProviderConfiguration{issuer: "https://issuer.example"},
            client_id: "oidc_client",
            client_secret: "secret_value"
          },
          %{refresh_jwks: _} = _opts
        ) do
      {:ok,
       %Oidcc.TokenIntrospection{
         active: true,
         client_id: "oidc_client",
         scope: ["openid", "profile"]
       }}
    end

    def introspect(_, _, _) do
      {:error, :not_defined}
    end
  end
end
