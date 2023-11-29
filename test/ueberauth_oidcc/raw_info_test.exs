defmodule UeberauthOidcc.RawInfoTest do
  use ExUnit.Case, async: true

  describe "inspect/1" do
    test "does not show a client_secret in the opts" do
      raw_info = %UeberauthOidcc.RawInfo{
        opts: %{client_secret: "secret_value"}
      }

      refute inspect(raw_info) =~ "secret_value"
    end

    test "does not show userinfo if it's missing" do
      raw_info = %UeberauthOidcc.RawInfo{}

      refute inspect(raw_info) =~ "userinfo"
    end

    test "does show userinfo if it's present" do
      raw_info = %UeberauthOidcc.RawInfo{
        userinfo: %{}
      }

      assert inspect(raw_info) =~ "userinfo: %{}"
    end
  end
end
