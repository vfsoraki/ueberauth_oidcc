defmodule UeberauthOidcc do
  @moduledoc """
  `UeberauthOidcc` is two things:

  - an implementation of `Ueberauth.Strategy`: see `Ueberauth.Strategy.Oidcc`
  - a set of modules for implementing other OpenID Connect (OIDC) strategies
  (see `UeberauthOidcc.Config`, `UeberauthOidcc.Request`,
  `UeberauthOidcc.Callback`, and `UeberauthOidcc.Error`)
  """

  @doc """
  Create a logout URL for a given `t:Ueberauth.Auth.t/0` struct.

  Also takes a an map of query parameters to append to the URL.
  """
  @spec initiate_logout_url(
          auth :: Ueberauth.Auth.t(),
          opts :: :oidcc_logout.initiate_url_opts() | :oidcc_client_context.opts()
        ) :: {:ok, String.t()} | {:error, term()}
  def initiate_logout_url(auth, params \\ %{})

  def initiate_logout_url(%Ueberauth.Auth{strategy: Ueberauth.Strategy.Oidcc} = auth, params) do
    id_token = auth.credentials.other.id_token

    initiate_logout_url(auth.extra.raw_info.opts, id_token, params)
  end

  def initiate_logout_url(%Ueberauth.Auth{} = auth, _params) do
    {:error, {:invalid_strategy, auth.strategy}}
  end

  @doc """
  Create a logout URL.

  Takes a `UeberauthOidcc.Config.t()`, an ID token value, and parameters to append to the URL.
  """
  @spec initiate_logout_url(
          UeberauthOidcc.Config.t(),
          id_token :: binary(),
          params :: :oidcc_logout.initiate_url_opts() | :oidcc_client_context.opts()
        ) :: {:ok, String.t()} | {:error, term()}
  def initiate_logout_url(opts, id_token, params) do
    opts = Map.merge(UeberauthOidcc.Config.default(), Map.new(opts))

    with {:ok, iodata} <-
           opts.module.initiate_logout_url(
             id_token,
             opts.issuer,
             opts.client_id,
             params
           ) do
      {:ok, IO.iodata_to_binary(iodata)}
    end
  end
end
