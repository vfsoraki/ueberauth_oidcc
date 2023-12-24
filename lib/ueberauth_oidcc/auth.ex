defmodule UeberauthOidcc.Auth do
  @moduledoc """
  Helper functions for converting an `Oidcc.Token.t()` and userinfo into `Ueberauth.Auth` structs.
  """

  @doc """
  Convert an `Oidcc.Token.t()` into an `Ueberauth.Auth.Credentials.t()`

  The ID token value is in the `extra` map as `id_token`.
  """
  @spec credentials(Oidcc.Token.t()) :: Ueberauth.Auth.Credentials.t()
  def credentials(%Oidcc.Token{} = token) do
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
      token_type: Map.get(token.access, :type, "Bearer"),
      expires: !!token.access.expires,
      expires_at: expires_at,
      scopes: token.scope,
      other: %{
        id_token: token.id.token
      }
    }
  end

  @doc """
  Converts an `Oidcc.Token.t()` and optional userinfo claims to an `Ueberauth.Auth.Info.t()`

  Uses the [OpenID Connect standard claims](https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims).
  """
  @spec info(Oidcc.Token.t()) :: Ueberauth.Auth.Info.t()
  @spec info(Oidcc.Token.t(), %{binary() => binary()}) :: Ueberauth.Auth.Info.t()
  def info(%Oidcc.Token{} = token, userinfo \\ %{}) do
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

  defp add_optional_url(urls, field, value)
  defp add_optional_url(urls, _field, nil), do: urls
  defp add_optional_url(urls, field, value), do: Map.put(urls, field, value)
end
