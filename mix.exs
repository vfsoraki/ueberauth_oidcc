defmodule UeberauthOidcc.MixProject do
  use Mix.Project

  def project do
    [
      app: :ueberauth_oidcc,
      version: "0.4.1",
      elixir: ">= 1.14.4 and < 2.0.0",
      name: "Ueberauth OIDCC",
      description: """
      An Ueberauth strategy for generic OpenID Connect (OIDC) authentication,
      and a library for implementing other OIDC strategies.

      Based on the Oidcc library.
      """,
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      docs: [
        main: "readme",
        extras: ["README.md", "CHANGELOG.md", "LICENSE"]
      ],
      package: package(),
      deps: deps(),
      dialyzer: dialyzer(),
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.cobertura": :test,
        "coveralls.html": :test
      ],
      test_coverage: [
        tool: ExCoveralls,
        ignore_modules: [FakeOidcc]
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["test/support" | elixirc_paths(:dev)]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [
      extra_applications: [:crypto],
      mod: {UeberauthOidcc.Application, []}
    ]
  end

  defp package do
    [
      maintainers: ["Paul Swartz"],
      licenses: ["MIT"],
      links: %{"GitLab" => "https://gitlab.com/paulswartz/ueberauth_oidcc"}
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.5", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.24", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.18.0", only: :test, runtime: false},
      oidcc(),
      {:plug, "~> 1.11"},
      {:ueberauth, "~> 0.10"}
    ]
  end

  defp oidcc do
    path = System.get_env("OIDCC_PATH", "")
    ref = System.get_env("OIDCC_REF", "")

    cond do
      path != "" ->
        {:oidcc, path: path}

      ref != "" ->
        {:oidcc, github: "erlef/oidcc", ref: ref}

      true ->
        {:oidcc, "~> 3.2.0"}
    end
  end

  defp dialyzer do
    if System.get_env("CI") do
      [
        plt_local_path: "_build/dialyzer",
        plt_core_path: "_build/dialyzer"
      ]
    else
      []
    end
  end
end
