import Config

config :gatekeep, ecto_repos: [Gatekeep.TestRepo]

config :gatekeep, Gatekeep.TestRepo,
  username: System.get_env("PGUSER", "postgres"),
  password: System.get_env("PGPASSWORD", "postgres"),
  hostname: System.get_env("PGHOST", "localhost"),
  database: "gatekeep_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10,
  priv: "test/support"

config :logger, level: :warning
