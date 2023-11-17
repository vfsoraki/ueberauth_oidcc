defmodule UeberauthOidccTest do
  @moduledoc false

  use ExUnit.Case, async: true

  @auth %Ueberauth.Auth{
    uid: "uid",
    strategy: Ueberauth.Strategy.Oidcc,
    credentials: %Ueberauth.Auth.Credentials{
      token: "access_token_value",
      other: %{
        id_token: "id_token_value"
      }
    },
    extra: %Ueberauth.Auth.Extra{
      raw_info: %{
        opts: %{
          issuer: :fake_issuer,
          module: FakeOidcc,
          client_id: "oidc_client"
        }
      }
    }
  }

  describe "initiate_logout_url/2" do
    test "calls Oidcc.initiate_logout_url/2 and returns a binary URL" do
      assert {:ok, url} = UeberauthOidcc.initiate_logout_url(@auth)
      assert String.starts_with?(url, "https://oidc.example/logout")
    end

    test "includes additional query parameters" do
      {:ok, url} =
        UeberauthOidcc.initiate_logout_url(@auth, %{
          post_logout_redirect_url: "https://redirect.example"
        })

      query = URI.decode_query(URI.parse(url).query)

      assert %{
               "post_logout_redirect_url" => "https://redirect.example"
             } = query
    end

    test "returns an error if Oidcc.initiate_logout_url/2 returns an error" do
      auth = put_in(@auth.credentials.other.id_token, "invalid_token")
      assert {:error, _} = UeberauthOidcc.initiate_logout_url(auth)
    end

    test "returns an error if the %Auth{} struct is for a different strategy" do
      auth = put_in(@auth.strategy, InvalidStrategy)
      assert {:error, _} = UeberauthOidcc.initiate_logout_url(auth)
    end
  end
end
