defmodule Gatekeep.TestRepo.Migrations.AddGatekeep do
  use Ecto.Migration

  def up, do: Gatekeep.Storage.Ecto.Migration.up(version: 1)
  def down, do: Gatekeep.Storage.Ecto.Migration.down(version: 1)
end
