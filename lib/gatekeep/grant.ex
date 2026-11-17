defmodule Gatekeep.Grant do
  @moduledoc """
  An extension grant of the token endpoint: a `grant_type` beyond
  `authorization_code` and `refresh_token`.

  `Gatekeep.TokenEndpoint` authenticates the client, checks that the client
  may use the grant type (its `grant_types`), and verifies any DPoP proof
  before it calls `c:token/5`. A grant module then checks its own input and
  issues a token with `Gatekeep.TokenEndpoint.issue_access_token/4`, using
  `Gatekeep.TokenEndpoint.grant_resource/3`,
  `Gatekeep.TokenEndpoint.check_resource_usable/3`,
  `Gatekeep.TokenEndpoint.client_scopes/3`, and
  `Gatekeep.TokenEndpoint.check_dpop_required/2` as needed.
  """

  alias Gatekeep.{Client, Config, TokenEndpoint}

  @doc "The `grant_type` the module handles."
  @callback grant_type() :: String.t()

  @doc "Whether `config` turns the grant on. An off grant is `unsupported_grant_type`."
  @callback enabled?(Config.t()) :: boolean()

  @doc """
  Handles a token request of the client `client`, which authenticated with
  `method`. `jkt` is the thumbprint of the request's verified DPoP proof key,
  or nil. Returns the token response body or an OAuth error code.
  """
  @callback token(
              Config.t(),
              Client.t(),
              method :: String.t(),
              params :: map(),
              jkt :: String.t() | nil
            ) :: {:ok, map()} | {:error, TokenEndpoint.error()}

  @doc "Fields the grant adds to the authorization server metadata (RFC 8414)."
  @callback metadata(Config.t()) :: map()

  @optional_callbacks metadata: 1
end
