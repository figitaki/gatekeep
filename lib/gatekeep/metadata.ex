defmodule Gatekeep.Metadata do
  @moduledoc """
  Discovery documents: authorization server metadata (RFC 8414) and
  protected resource metadata (RFC 9728).
  """

  alias Gatekeep.{Config, Resource}

  @jwt_bearer "urn:ietf:params:oauth:grant-type:jwt-bearer"

  @doc "Authorization server metadata (RFC 8414 §2) for the issuer and its enabled resources."
  @spec authorization_server(Config.t()) :: map()
  def authorization_server(%Config{} = config) do
    resources = Config.enabled_resources(config)
    methods = resources |> Enum.flat_map(& &1.client_auth_methods) |> Enum.uniq()
    public? = "none" in methods
    jwt_methods = Enum.filter(methods, &(&1 == "private_key_jwt")) != []
    enterprise? = not is_nil(config.enterprise)
    client_credentials? = Enum.any?(config.clients, &("client_credentials" in &1.grant_types))

    grant_types =
      ["authorization_code", "refresh_token"] ++
        if(client_credentials?, do: ["client_credentials"], else: []) ++
        if(enterprise?, do: [@jwt_bearer], else: [])

    %{
      "issuer" => config.issuer,
      "authorization_endpoint" => Config.endpoint(config, :authorize),
      "token_endpoint" => Config.endpoint(config, :token),
      "revocation_endpoint" => Config.endpoint(config, :revoke),
      "registration_endpoint" => if(public?, do: Config.endpoint(config, :register)),
      "jwks_uri" => if(config.access_token_format == :jwt, do: Config.endpoint(config, :jwks)),
      "response_types_supported" => ["code"],
      "response_modes_supported" => ["query"],
      "grant_types_supported" => grant_types,
      "code_challenge_methods_supported" => ["S256"],
      "token_endpoint_auth_methods_supported" => methods,
      "token_endpoint_auth_signing_alg_values_supported" =>
        if(jwt_methods, do: config.client_assertion_algs),
      "revocation_endpoint_auth_methods_supported" => methods,
      "revocation_endpoint_auth_signing_alg_values_supported" =>
        if(jwt_methods, do: config.client_assertion_algs),
      "dpop_signing_alg_values_supported" => config.dpop_signing_algs,
      "authorization_response_iss_parameter_supported" => true,
      "client_id_metadata_document_supported" => true,
      "authorization_grant_profiles_supported" =>
        if(enterprise?, do: ["urn:ietf:params:oauth:grant-profile:id-jag"]),
      "scopes_supported" => resources |> Enum.flat_map(& &1.scope_names) |> Enum.uniq()
    }
    |> Map.reject(fn {_key, value} -> is_nil(value) end)
  end

  @doc "Protected resource metadata (RFC 9728 §2) of `resource`."
  @spec protected_resource(Config.t(), Resource.t()) :: map()
  def protected_resource(%Config{} = config, %Resource{} = resource) do
    resource.metadata
    |> Map.merge(%{
      "resource" => resource.id,
      "authorization_servers" => [config.issuer],
      "scopes_supported" => resource.scope_names,
      "bearer_methods_supported" => ["header"],
      "dpop_signing_alg_values_supported" => config.dpop_signing_algs,
      "dpop_bound_access_tokens_required" => resource.dpop == :required
    })
    |> then(&if(resource.name, do: Map.put(&1, "resource_name", resource.name), else: &1))
  end

  @doc "The JWKS document of the configured signer."
  @spec jwks(Config.t()) :: map()
  def jwks(%Config{} = config), do: %{"keys" => Gatekeep.Signer.public_keys(config)}
end
