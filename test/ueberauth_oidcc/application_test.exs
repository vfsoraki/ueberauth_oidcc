defmodule UeberauthOidcc.ApplicationTest do
  @moduledoc false
  use ExUnit.Case

  describe "start/2" do
    setup do
      old_config = Application.get_all_env(:ueberauth_oidcc)

      on_exit(fn ->
        Application.put_all_env(ueberauth_oidcc: old_config)
      end)

      :ok
    end

    test "supports running multiple Oidcc.ProviderConfiguration.Worker children" do
      config = [
        issuers: [
          %{name: :one, issuer: "https://accounts.google.com/"},
          %{name: :two, issuer: "https://accounts.google.com/"}
        ]
      ]

      Application.put_all_env(ueberauth_oidcc: config)
      Application.stop(:ueberauth_oidcc)

      assert {:ok, pid} = UeberauthOidcc.Application.start(:normal, [])
      assert %{active: 2} = Supervisor.count_children(pid)
    end
  end
end
