defmodule UeberauthOidcc.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      for child_opts <- Application.get_env(:ueberauth_oidcc, :issuers) || [] do
        {Oidcc.ProviderConfiguration.Worker, child_opts}
      end

    opts = [strategy: :one_for_one, name: UeberauthOidcc.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
