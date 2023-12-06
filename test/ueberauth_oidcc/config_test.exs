defmodule UeberauthOidcc.ConfigTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias UeberauthOidcc.Config

  describe "merge_and_expand_configuration/1" do
    test "merges configurations and expands tuples" do
      configurations = [
        %{default: :value, override: false},
        [system_no_default: {:system, "PATH"}],
        %{mfa: {System, :fetch_env, ["PATH"]}},
        %{system_missing: {:system, "MISSING"}},
        %{system_missing_default: {:system, "MISSING", "default"}},
        %{override: fn -> true end}
      ]

      merged = Config.merge_and_expand_configuration(configurations)

      assert %{
               default: :value,
               override: true,
               system_no_default: _,
               mfa: _,
               system_missing_default: "default"
             } = merged

      refute Map.has_key?(merged, :system_missing)
    end
  end
end
