defmodule UeberauthOidcc.ErrorTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import UeberauthOidcc.Error

  alias Ueberauth.Failure.Error

  describe "describe_error/2" do
    test "describes an invalid claim" do
      reason = {:missing_claim, {"claim", "value"}, %{"claim" => "actual"}}

      assert %Error{
               message_key: "claim",
               message: "Received invalid claim claim: expected \"value\", got \"actual\""
             } = describe_error(reason, "key")
    end

    test "describes a missing claim" do
      reason = {:missing_claim, "claim", %{}}

      assert %Error{
               message_key: "claim",
               message: "Missing required claim claim"
             } = describe_error(reason, "key")
    end
  end
end
