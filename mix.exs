defmodule UeberauthOidcc.MixProject do
  use Mix.Project

  def project do
    [
      app: :ueberauth_oidcc,
      version: "0.1.0",
      elixir: ">= 1.14.4 and < 2.0.0",
      description: """
      An Ueberauth strategy for generic OpenID Connect authentication.

      Based on the Oidcc library.
      """,
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      docs: [
        main: "readme",
        extras: ["README.md", "LICENSE"]
      ],
      package: package(),
      deps: deps(),
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
      extra_applications: [:logger],
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
      {:oidcc, "~> 3.1.0"},
      {:plug, "~> 1.11"},
      {:ueberauth, "~> 0.10.5"}
    ]
  end
end
