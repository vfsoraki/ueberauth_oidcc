defmodule UeberauthOidcc do
  @moduledoc """
  Documentation for `UeberauthOidcc`.
  """

  @doc """
  Create a logout URL for a given `t:Ueberauth.Auth.t/0` struct.

  Also takes a an map of query parameters to append to the URL.
  """
  @spec initiate_logout_url(
          auth :: Ueberauth.Auth.t(),
          opts :: :oidcc_logout.initiate_url_opts() | :oidcc_client_context.opts()
        ) :: {:ok, String.t()} | {:error, term()}
  def initiate_logout_url(auth, opts \\ %{})

  def initiate_logout_url(%Ueberauth.Auth{strategy: Ueberauth.Strategy.Oidcc} = auth, opts) do
    strategy_opts = auth.extra.raw_info.opts
    id_token = auth.credentials.other.id_token

    case strategy_opts.module.initiate_logout_url(
           id_token,
           strategy_opts.issuer,
           strategy_opts.client_id,
           opts
         ) do
      {:ok, iodata} -> {:ok, IO.iodata_to_binary(iodata)}
      other -> other
    end
  end

  def initiate_logout_url(%Ueberauth.Auth{} = auth, _params) do
    {:error, {:invalid_strategy, auth.strategy}}
  end
end
