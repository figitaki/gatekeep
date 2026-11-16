defmodule Gatekeep.MixProject do
  use Mix.Project

  @version "0.1.0-alpha.1"
  @source_url "https://github.com/figitaki/gatekeep"

  def project do
    [
      app: :gatekeep,
      version: @version,
      elixir: "~> 1.19",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      description:
        "An OAuth 2.1 authorization server and protected-resource toolkit for MCP servers.",
      package: package(),
      docs: docs(),
      source_url: @source_url,
      homepage_url: @source_url,
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit],
        plt_local_path: "priv/plts",
        plt_core_path: "priv/plts"
      ]
    ]
  end

  def cli do
    [preferred_envs: [ci: :test, "ecto.create": :test, "ecto.migrate": :test]]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key, :ssl, :inets]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:plug, "~> 1.16"},
      {:ecto_sql, "~> 3.12"},
      {:nimble_options, "~> 1.1"},
      {:postgrex, "~> 0.19", optional: true},
      {:fastest_mcp, "~> 1.0", optional: true},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"],
      ci: ["format --check-formatted", "compile --warnings-as-errors", "credo --strict", "test"]
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "https://hexdocs.pm/gatekeep/changelog.html"
      },
      files: ~w(lib mix.exs README.md LICENSE CHANGELOG.md guides)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url: @source_url,
      source_ref: "v#{@version}",
      extras: [
        "README.md": [title: "Overview"],
        "guides/getting_started.md": [title: "Getting started"],
        "guides/fastest_mcp.md": [title: "Protecting a FastestMCP server"],
        "guides/security.md": [title: "Security notes"],
        "CHANGELOG.md": [title: "Changelog"],
        LICENSE: [title: "License"]
      ],
      groups_for_extras: [Guides: ~r{guides/}],
      groups_for_modules: [
        "Authorization server": [
          Gatekeep,
          Gatekeep.Config,
          Gatekeep.Authorization,
          Gatekeep.TokenEndpoint,
          Gatekeep.Registration,
          Gatekeep.Metadata
        ],
        "Protected resources": [Gatekeep.Resource, Gatekeep.Token, Gatekeep.FastestMCP],
        Plugs: [Gatekeep.Plug.Endpoints, Gatekeep.Plug.Authorize, Gatekeep.Plug.Resource],
        "Extension points": [
          Gatekeep.Consent,
          Gatekeep.Grant,
          Gatekeep.Storage,
          Gatekeep.Signer,
          Gatekeep.Signer.Local,
          Gatekeep.Fetcher
        ],
        Storage: [Gatekeep.Storage.Ecto, Gatekeep.Storage.Ecto.Migration],
        Internals: [
          Gatekeep.Client,
          Gatekeep.ClientAuth,
          Gatekeep.Clients,
          Gatekeep.DPoP,
          Gatekeep.JOSE
        ]
      ]
    ]
  end
end
