defmodule UeberauthOidcc.Helpers do
  @moduledoc false

  @doc false
  @spec opts_with_refresh(opts) :: opts when opts: map()
  def opts_with_refresh(%{refresh_jwks: _} = opts) do
    opts
  end

  def opts_with_refresh(%{issuer: issuer} = opts) do
    refresh_jwks_fn = :oidcc_jwt_util.refresh_jwks_fun(issuer)
    Map.put(opts, :refresh_jwks, refresh_jwks_fn)
  end

  def opts_with_refresh(%{} = opts) do
    opts
  end

  @doc false
  @spec client_context(opts :: map(), provider_overrides :: map()) ::
          {:ok, Oidcc.ClientContext.t(), opts :: map()} | {:error, term}
  def client_context(opts, provider_overrides)

  def client_context(%{issuer: _, client_id: _, client_secret: _} = opts, provider_overrides) do
    with {:ok, client_context} <-
           apply_oidcc(opts, [ClientContext], :from_configuration_worker, [
             opts.issuer,
             opts.client_id,
             opts.client_secret,
             opts
           ]),
         opts = Map.drop(opts, ~w[issuer client_id client_secret]a),
         {:ok, client_context, opts} <- Oidcc.ClientContext.apply_profiles(client_context, opts) do
      client_context = %{
        client_context
        | provider_configuration:
            Map.merge(client_context.provider_configuration, provider_overrides)
      }

      {:ok, client_context, opts}
    end
  end

  def client_context(%{client_id: _, client_secret: _}, _overrides) do
    {:error, {:missing_config, :issuer}}
  end

  def client_context(%{client_secret: _}, _overrides) do
    {:error, {:missing_config, :client_id}}
  end

  def client_context(%{}, _overrides) do
    {:error, {:missing_config, :client_secret}}
  end

  @doc false
  def apply_oidcc(opts, additional_mods, fun, args) do
    mod = Module.concat([opts.module | additional_mods])
    apply(mod, fun, args)
  end

  @doc false
  def url_encode64(bytes) do
    Base.url_encode64(bytes, padding: false)
  end
end
