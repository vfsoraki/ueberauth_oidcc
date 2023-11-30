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

  def create_redirect_url(provider_configuration_name, client_id, client_secret, opts)

  def create_redirect_url(:fake_issuer, "oidc_client" = client_id, :unauthenticated, opts) do
    params = %{
      client_id: client_id,
      redirect_uri: opts[:redirect_uri],
      state: opts[:state],
      nonce: opts[:nonce],
      response_type: opts[:response_type],
      scope: Enum.join(Map.get(opts, :scopes, []), " ")
    }

    extension =
      case Map.fetch(opts, :url_extension) do
        {:ok, e} -> ["&", URI.encode_query(e)]
        :error -> []
      end

    query = URI.encode_query(params)

    {:ok, [request_url(), "?", query, extension]}
  end

  def create_redirect_url(_, _, _, _) do
    {:error, :not_defined}
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

  def retrieve_token(auth_code, provider_configuration_name, client_id, client_secret, opts)

  def retrieve_token(_, _, _, _, %{:_retrieve_token => false}) do
    {:error, :no_tokens}
  end

  def retrieve_token(
        auth_code,
        provider_configuration_name,
        client_id,
        client_secret,
        %{:_retrieve_token => :alg_none} = opts
      ) do
    opts = Map.delete(opts, :_retrieve_token)

    case retrieve_token(auth_code, provider_configuration_name, client_id, client_secret, opts) do
      {:ok, token} ->
        {:error, {:none_alg_used, token}}

      {:error, _} = e ->
        e
    end
  end

  def retrieve_token(
        auth_code,
        provider_configuration_name,
        client_id,
        client_secret,
        %{:_retrieve_token => :invalid_nonce} = opts
      ) do
    opts = Map.delete(opts, :_retrieve_token)

    case retrieve_token(auth_code, provider_configuration_name, client_id, client_secret, opts) do
      {:ok, %{id: %{claims: claims}}} ->
        {:error, {:missing_claim, {:nonce, Map.get(opts, :nonce), claims}}}

      {:error, _} = e ->
        e
    end
  end

  def retrieve_token(auth_code, :fake_issuer, "oidc_client", "secret_value", opts) do
    if auth_code == callback_code() do
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

  def retrieve_token(_, _, _, _, _) do
    {:error, :not_defined}
  end

  def retrieve_userinfo(token, provider_configuration_name, client_id, client_secret, opts \\ %{})

  def retrieve_userinfo(_, _, _, _, %{:_retrieve_userinfo => false}) do
    {:error, :no_userinfo}
  end

  def retrieve_userinfo(
        %Oidcc.Token{access: %Oidcc.Token.Access{token: "access_token_value"}},
        :fake_issuer,
        "oidc_client",
        "secret_value",
        _opts
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

  def retrieve_userinfo(_, _, _, _, _) do
    {:error, :not_defined}
  end
end
