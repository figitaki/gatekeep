defmodule Gatekeep.Enterprise do
  @moduledoc """
  Enterprise-managed authorization: the MCP extension
  `io.modelcontextprotocol/enterprise-managed-authorization` (protocol
  revision 2026-07-28), which profiles the Identity Assertion JWT
  Authorization Grant (ID-JAG, draft-ietf-oauth-identity-assertion-authz-grant).

  A user signed in to an MCP client through their company's identity
  provider (IdP). The client exchanges the user's identity token at the IdP
  for an ID-JAG (RFC 8693 token exchange, the IdP's job), then presents it
  here with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`. Gatekeep
  validates it and issues an access token, with no browser and no consent
  page: the IdP's policy is the consent.

  Turn it on with an `:enterprise` config naming a module that implements
  this behaviour:

      enterprise: [module: MyApp.EnterpriseTrust]

  The metadata then lists the `jwt-bearer` grant type and the
  `urn:ietf:params:oauth:grant-profile:id-jag` grant profile.

  ## What Gatekeep checks

  In this order, refusing with `invalid_grant` on any failure:

    1. **Issuer.** `c:trusted_issuer/3` must accept the assertion's `iss`
       (exact string) for the request's client, before any key is fetched.
       It returns where the issuer's keys are: a `:jwks` list, or else the
       `jwks_uri` of `<iss>/.well-known/openid-configuration`, whose `issuer`
       must equal `iss`. Keys are cached, and an unknown `kid` refetches them
       at most every 30 seconds.
    2. **Signature.** ES256 or RS256 by a key of that key set. Keys named in
       the assertion's header are ignored.
    3. **Type.** The `typ` header is `oauth-id-jag+jwt`.
    4. **Audience.** `aud` is this issuer, as a string or a one-element list.
    5. **Client.** The `client_id` claim is the client of the request.
    6. **Subject.** `sub` is present.
    7. **Time.** `exp` has not passed, `iat` is not in the future, `nbf` (if
       present) has passed, all within `:clock_skew`, and `exp - iat` is at
       most `:max_assertion_lifetime`.
    8. **Replay.** `jti` is present and not seen before from this issuer.
    9. **Resource.** A `resource` claim must name a resource this issuer
       serves, and the `resource` parameter, if any, must match it. Without
       the claim, the parameter or `:default_resource` picks the resource,
       unless `:require_resource_claim` is set. The access token is
       audience-restricted to that resource.
    10. **Scope.** The `scope` claim's scopes that the resource offers, or the
        resource's defaults without the claim, narrowed by the request's
        `scope` parameter.
    11. **Key binding.** With a `cnf` claim, the request needs a DPoP proof
        from the `cnf.jkt` key (RFC 9449); other confirmation methods are
        refused. The access token is then DPoP-bound.

  Then `c:resolve_subject/2` maps the identity to a local subject, or
  refuses with `access_denied` (the user exists at the IdP but not here).

  No refresh token is issued: the client gets a fresh ID-JAG from the IdP
  instead, which keeps the IdP's policy in force.
  """

  alias Gatekeep.{Cache, Client, Config, Fetcher, JOSE, Storage, TokenEndpoint, Util}

  @typ "oauth-id-jag+jwt"
  @algs ["ES256", "RS256"]
  @refetch_interval 30

  @typedoc """
  Where to find a trusted issuer's keys: `jwks: [jwk]`, or nothing to use
  OpenID discovery at `<iss>/.well-known/openid-configuration`. Anything
  else in the map is passed on to `c:resolve_subject/2`, such as the tenant
  the issuer belongs to.
  """
  @type issuer :: map()

  @doc """
  Whether to trust identity assertions from `iss` presented by `client`.
  Compare `iss` exactly with the issuer a tenant registered; a prefix or host
  match admits other tenants' users. When one issuer serves several of your
  tenants, use the (still unverified) `claims` such as `aud_tenant` only to
  pick the tenant, and check its registered issuer.

  `claims` are not verified yet when this is called.
  """
  @callback trusted_issuer(iss :: String.t(), claims :: map(), client :: Client.t()) ::
              {:ok, issuer()} | :error

  @doc """
  Maps a verified identity assertion to a local subject. Return
  `{:ok, opts}` with `:subject` (required), and optionally `:owner`,
  `:claims` (kept with the grant), and `:scopes` (to narrow what the
  assertion grants). Return `{:error, :access_denied}` when the user may not
  use this server, such as no account in the resolved tenant.

  Prefer `iss` and `sub` (and `tenant` for multi-tenant issuers) as the
  stable key. Match by `email` only when your service verified that address
  or its domain for the tenant: whoever runs an IdP can put any address in
  `email`.
  """
  @callback resolve_subject(claims :: map(), issuer()) ::
              {:ok, keyword()} | {:error, :access_denied}

  @doc false
  def exchange(%Config{enterprise: nil}, _client, _method, _params, _jkt),
    do: {:error, :unsupported_grant_type}

  def exchange(%Config{} = config, client, method, params, jkt) do
    with {:ok, claims, trust} <- verify(config, params["assertion"], client, jkt),
         {:ok, resource} <- resource(config, claims, params["resource"]),
         :ok <- Util.expect(method in resource.client_auth_methods, :unauthorized_client),
         :ok <-
           if(resource.dpop == :required and is_nil(jkt),
             do: {:error, :invalid_dpop_proof},
             else: :ok
           ),
         {:ok, scopes} <- scopes(resource, client, claims["scope"], params["scope"]),
         {:ok, local} <- resolve(config, claims, trust),
         {:ok, scopes} <- narrow(scopes, local[:scopes]) do
      {:ok, grant} =
        Storage.call(config, :insert_grant, [
          %{
            client_id: client.client_id,
            client_name: client.client_name,
            subject: to_string(Keyword.fetch!(local, :subject)),
            owner: local[:owner] && to_string(local[:owner]),
            resource: resource.id,
            scopes: scopes,
            claims: Keyword.get(local, :claims, %{}),
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
            dpop_jkt: jkt,
            expires_at: Util.in_seconds(config.access_token_ttl)
          }
        ])

      {:ok, TokenEndpoint.issue_access_token(config, grant, scopes, jkt)}
    else
      {:error, reason}
      when reason in [
             :invalid_scope,
             :invalid_target,
             :access_denied,
             :unauthorized_client,
             :invalid_dpop_proof
           ] ->
        {:error, reason}

      _ ->
        {:error, :invalid_grant}
    end
  end

  @doc """
  Verifies an identity assertion for `client`, as steps 1 to 8 and 11 of the
  module docs describe. `jkt` is the thumbprint of the request's verified
  DPoP proof key, or nil. Returns the claims and the issuer's trust map, or
  why the assertion was refused. `opts[:now]` overrides the Unix time.
  """
  @spec verify(Config.t(), term(), Client.t(), String.t() | nil, keyword()) ::
          {:ok, map(), issuer()} | {:error, atom()}
  def verify(%Config{enterprise: enterprise} = config, assertion, client, jkt, opts \\ []) do
    now = Keyword.get_lazy(opts, :now, &Util.now/0)
    skew = config.clock_skew
    module = enterprise[:module]

    with {:ok, jws} <- JOSE.decode(assertion),
         %{"iss" => iss} when is_binary(iss) and iss != "" <- jws.claims,
         {:ok, trust} <- trusted(module, iss, jws.claims, client),
         :ok <- verify_signature(config, jws, iss, trust),
         :ok <- Util.expect(jws.header["typ"] == @typ, :bad_typ),
         claims = jws.claims,
         :ok <- Util.expect(audience?(claims["aud"], config.issuer), :wrong_audience),
         :ok <- Util.expect(claims["client_id"] == client.client_id, :client_mismatch),
         :ok <- Util.expect(is_binary(claims["sub"]) and claims["sub"] != "", :missing_sub),
         %{"exp" => exp, "iat" => iat} when is_integer(exp) and is_integer(iat) <- claims,
         :ok <- Util.expect(exp > now - skew, :expired),
         :ok <- Util.expect(iat <= now + skew, :issued_in_future),
         :ok <-
           Util.expect(not is_integer(claims["nbf"]) or claims["nbf"] <= now + skew, :not_yet_valid),
         :ok <- Util.expect(is_nil(claims["nbf"]) or is_integer(claims["nbf"]), :bad_nbf),
         :ok <- Util.expect(exp - iat <= enterprise[:max_assertion_lifetime], :assertion_too_long),
         :ok <- check_cnf(claims["cnf"], jkt),
         jti when is_binary(jti) and jti != "" and byte_size(jti) <= 255 <- claims["jti"],
         :ok <-
           Storage.call(config, :remember_jti, ["id_jag", iss, jti, DateTime.from_unix!(exp + skew)]) do
      {:ok, claims, trust}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_assertion}
    end
  end

  defp trusted(module, iss, claims, client) do
    case module.trusted_issuer(iss, claims, client) do
      {:ok, trust} when is_map(trust) -> {:ok, Map.put(trust, :issuer, iss)}
      _ -> {:error, :untrusted_issuer}
    end
  end

  # One audience, this issuer: a string, or a list of exactly one.
  defp audience?(aud, issuer) when is_binary(aud), do: aud == issuer
  defp audience?([aud], issuer) when is_binary(aud), do: aud == issuer
  defp audience?(_aud, _issuer), do: false

  # RFC 9449 key binding (draft §9.11): a bound assertion needs a proof from
  # its key; an unsupported confirmation method is refused.
  defp check_cnf(nil, _jkt), do: :ok

  defp check_cnf(%{"jkt" => bound} = cnf, jkt) when map_size(cnf) == 1 and is_binary(bound),
    do: Util.expect(bound == jkt, :key_binding_mismatch)

  defp check_cnf(_cnf, _jkt), do: {:error, :unsupported_cnf}

  defp verify_signature(config, jws, iss, trust) do
    if jws.header["alg"] in @algs do
      kid = jws.header["kid"]

      keys =
        case issuer_keys(config, iss, trust, kid) do
          {:ok, keys} -> if is_binary(kid), do: Enum.filter(keys, &(&1["kid"] == kid)), else: keys
          {:error, _} -> []
        end

      if Enum.any?(keys, &JOSE.verify(jws, &1, @algs)), do: :ok, else: {:error, :bad_signature}
    else
      {:error, :bad_alg}
    end
  end

  defp issuer_keys(_config, _iss, %{jwks: keys}, _kid) when is_list(keys),
    do: {:ok, Enum.filter(keys, &JOSE.public_key?/1)}

  defp issuer_keys(config, iss, _trust, kid) do
    key = {:enterprise_jwks, iss}

    case Cache.lookup(config.name, key) do
      {:ok, keys, fetched_at} ->
        if is_binary(kid) and not Enum.any?(keys, &(&1["kid"] == kid)) and
             Util.now() - fetched_at >= @refetch_interval,
           do: Cache.single_flight(config.name, key, fn -> load_keys(config, iss) end),
           else: {:ok, keys}

      :miss ->
        Cache.single_flight(config.name, key, fn ->
          case Cache.lookup(config.name, key) do
            {:ok, keys, _} -> {:ok, keys}
            :miss -> load_keys(config, iss)
          end
        end)
    end
  end

  defp load_keys(config, iss) do
    discovery = String.trim_trailing(iss, "/") <> "/.well-known/openid-configuration"

    with {:ok, %{"issuer" => ^iss, "jwks_uri" => jwks_uri}} when is_binary(jwks_uri) <-
           Fetcher.fetch_json(discovery, config),
         {:ok, keys} <- Gatekeep.Clients.fetch_keys(config, jwks_uri) do
      Cache.put(
        config.name,
        {:enterprise_jwks, iss},
        keys,
        config.client_cache_seconds,
        config.client_cache_size
      )

      {:ok, keys}
    else
      _ -> {:error, :keys_unavailable}
    end
  end

  defp resource(config, claims, param) do
    claim = claims["resource"]

    cond do
      is_binary(claim) ->
        case Enum.find(Config.enabled_resources(config), &Util.same_url?(claim, &1.id)) do
          nil ->
            {:error, :invalid_grant}

          resource ->
            if is_nil(param) or Util.same_url?(param, resource.id),
              do: {:ok, resource},
              else: {:error, :invalid_target}
        end

      not is_nil(claim) ->
        {:error, :invalid_grant}

      config.enterprise[:require_resource_claim] ->
        {:error, :invalid_grant}

      true ->
        TokenEndpoint.grant_resource(config, param, nil)
    end
  end

  # The IdP's grant, limited to what the resource and client offer, then
  # narrowed by the request.
  defp scopes(resource, client, claim, param) do
    offered =
      case Util.split_scope(claim) do
        [] when is_nil(claim) -> resource.default_scopes
        scopes -> Enum.filter(resource.scope_names, &(&1 in scopes))
      end

    offered = if client.scopes, do: Enum.filter(offered, &(&1 in client.scopes)), else: offered

    with {:ok, scopes} <- narrow(offered, param && Util.split_scope(param)),
         true <- scopes != [] do
      {:ok, scopes}
    else
      _ -> {:error, :invalid_scope}
    end
  end

  defp narrow(scopes, nil), do: {:ok, scopes}
  defp narrow(scopes, []), do: {:ok, scopes}

  defp narrow(scopes, requested) when is_list(requested) do
    if requested -- scopes == [],
      do: {:ok, Enum.filter(scopes, &(&1 in requested))},
      else: {:error, :invalid_scope}
  end

  defp resolve(config, claims, trust) do
    case config.enterprise[:module].resolve_subject(claims, trust) do
      {:ok, local} when is_list(local) ->
        if Keyword.has_key?(local, :subject), do: {:ok, local}, else: {:error, :access_denied}

      _ ->
        {:error, :access_denied}
    end
  end
end
