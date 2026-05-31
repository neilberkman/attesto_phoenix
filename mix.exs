defmodule AttestoPhoenix.MixProject do
  @moduledoc false
  use Mix.Project

  @version "0.6.1"
  @url "https://github.com/neilberkman/attesto_phoenix"
  @maintainers ["Neil Berkman"]

  def project do
    [
      name: "AttestoPhoenix",
      app: :attesto_phoenix,
      version: @version,
      elixir: "~> 1.18",
      package: package(),
      source_url: @url,
      homepage_url: @url,
      maintainers: @maintainers,
      description:
        "Phoenix/Ecto OAuth 2.0 / OIDC authorization server layer over attesto: " <>
          "authorization, token, PAR, revocation, discovery, JWKS, UserInfo, " <>
          "protected-resource plugs, and Ecto-backed token stores.",
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      docs: docs(),
      aliases: aliases(),
      dialyzer: [
        ignore_warnings: ".dialyzer_ignore.exs",
        plt_add_apps: [:mix, :ex_unit],
        plt_core_path: "priv/plts",
        plt_file: {:no_warn, "priv/plts/attesto_phoenix.plt"}
      ]
    ]
  end

  def cli do
    [preferred_envs: [precommit: :test]]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Core OAuth2/OIDC primitives: Token, IDToken, DPoP, MTLS, Scope,
      # AuthorizationCode, AuthorizationRequest, RefreshToken, Discovery,
      # OpenIDDiscovery, the store behaviours, and the base plugs.
      {:attesto, "~> 0.6"},
      # Ecto-backed CodeStore/RefreshStore/NonceStore/ReplayCheck + the migration
      # generator.
      {:ecto_sql, "~> 3.10"},
      # Controllers + the attesto_routes/1 router macro.
      {:phoenix, "~> 1.7"},
      # Plug behaviours for the protected-resource plugs (also a Phoenix
      # transitive dependency).
      {:plug, "~> 1.15"},
      # JSON encoding for token/discovery/JWKS responses.
      {:jason, "~> 1.4"},

      # test - the bundled Ecto stores run against a real Postgres repo.
      {:postgrex, ">= 0.0.0", only: [:dev, :test]},

      # dev / quality
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:mix_test_watch, "~> 1.4", only: :dev, runtime: false},
      {:quokka, "~> 2.12", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      setup: ["deps.get"],
      precommit: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        "test"
      ]
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @url,
      extras: ["README.md", "CHANGELOG.md", "LICENSE"],
      groups_for_extras: [
        Changelog: ~r/CHANGELOG\.md/,
        License: ~r/LICENSE/
      ],
      groups_for_modules: [
        Setup: [AttestoPhoenix, AttestoPhoenix.Config, AttestoPhoenix.Router],
        Controllers: [
          AttestoPhoenix.Controller.TokenController,
          AttestoPhoenix.Controller.RevocationController,
          AttestoPhoenix.Controller.DiscoveryController,
          AttestoPhoenix.Controller.JWKSController,
          AttestoPhoenix.Controller.PARController,
          AttestoPhoenix.Controller.RegistrationController,
          AttestoPhoenix.Controller.UserinfoController
        ],
        Stores: [
          AttestoPhoenix.Store.EctoCodeStore,
          AttestoPhoenix.Store.EctoRefreshStore,
          AttestoPhoenix.Store.EctoReplayCheck,
          AttestoPhoenix.Store.EctoNonceStore,
          AttestoPhoenix.Store.PAR.ETS,
          AttestoPhoenix.Store.Sweeper
        ],
        Schemas: [
          AttestoPhoenix.Schema.Authorization,
          AttestoPhoenix.Schema.RefreshToken,
          AttestoPhoenix.Schema.DPoPReplay,
          AttestoPhoenix.Schema.DPoPNonce
        ],
        Shared: [
          AttestoPhoenix.OAuthError,
          AttestoPhoenix.Event,
          AttestoPhoenix.PARStore,
          AttestoPhoenix.RequestContext
        ]
      ]
    ]
  end

  defp package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{
        "Changelog" => "https://hexdocs.pm/attesto_phoenix/changelog.html",
        "GitHub" => @url
      },
      files: ~w(lib LICENSE mix.exs README.md CHANGELOG.md)
    ]
  end
end
