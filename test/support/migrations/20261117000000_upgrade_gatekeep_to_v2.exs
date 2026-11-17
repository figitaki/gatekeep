defmodule Gatekeep.TestRepo.Migrations.UpgradeGatekeepToV2 do
  use Ecto.Migration

  def up, do: Gatekeep.Storage.Ecto.Migration.up(version: 2)
  def down, do: Gatekeep.Storage.Ecto.Migration.down(version: 2)
end
