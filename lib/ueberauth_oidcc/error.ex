defmodule UeberauthOidcc.Error do
  @moduledoc """
  Handles errors returned from the request/callback functions.
  """

  import Ueberauth.Strategy.Helpers,
    only: [set_errors!: 2, error: 2]

  @doc """
  Renders the given error reason as an `Ueberauth.Failure.t()` on the
  `Plug.Conn.t()`.

  `message_key` will be used as the default `message_key` if a better one is
  unavailable.
  """
  @spec set_described_error(Plug.Conn.t(), reason :: term(), message_key :: binary()) ::
          Plug.Conn.t()
  def set_described_error(conn, reason, message_key) do
    error = describe_error(reason, message_key)

    set_errors!(conn, [error])
  end

  @doc """
  Renders the given error as an `Ueberauth.Failure.Error.t()`.

  `message_key` will be used as the default `message_key` if a better one is
  unavailable.
  """
  @spec describe_error(reason :: term(), message_key :: binary()) :: Ueberauth.Failure.Error.t()
  def describe_error(reason, message_key)

  def describe_error({:missing_config, config_key}, _key) do
    error("config", "Missing #{config_key}")
  end

  def describe_error(:missing_code, _key) do
    error("code", "Query string does not contain field 'code'")
  end

  def describe_error(:invalid_state, _key) do
    # same error as https://github.com/ueberauth/ueberauth/blob/master/lib/ueberauth/strategy.ex#L363C1-L363C87
    error("csrf_attack", "Cross-Site Request Forgery attack")
  end

  def describe_error({:invalid_issuer, issuer, expected}, _key) do
    error("issuer", "Expected code for issuer #{expected}, but got callback for #{issuer}")
  end

  def describe_error(:missing_issuer, _key) do
    error(
      "iss",
      "Missing expected iss param"
    )
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

  def describe_error({:missing_claim, {claim, expected_value}, claims}, _key) do
    actual_value = Map.get(claims, claim)

    error(
      claim,
      "Received invalid claim #{claim}: expected #{inspect(expected_value)}, got #{inspect(actual_value)}"
    )
  end

  def describe_error({:missing_claim, claim, _claims}, _key) do
    error(
      claim,
      "Missing required claim #{claim}"
    )
  end

  def describe_error({:no_matching_key_with_kid, _}, key) do
    error(
      key,
      "Invalid signature"
    )
  end

  def describe_error(:no_matching_key, key) do
    error(
      key,
      "Invalid signature"
    )
  end

  def describe_error(:bad_subject, _key) do
    error(
      "sub",
      "Invalid subject"
    )
  end

  def describe_error({:http_error, _code, %{"error" => error} = body}, _key) do
    description = Map.get(body, "error_description", "")

    error(
      error,
      description
    )
  end

  def describe_error({:jarm_error, %{"error" => error} = body}, _key) do
    # https://openid.net/specs/oauth-v2-jarm.html#name-example-response-type-code
    description = Map.get(body, "error_description", "")

    error(
      error,
      description
    )
  end

  def describe_error({:use_dpop_nonce, nonce, _}, _key) do
    error(
      "use_dpop_nonce",
      nonce
    )
  end

  def describe_error(reason, message_key) do
    error(message_key, inspect(reason))
  end
end
