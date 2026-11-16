defmodule Gatekeep.EnterpriseTest do
  use Gatekeep.Case

  @idp "https://idp.test"
  @jwt_bearer "urn:ietf:params:oauth:grant-type:jwt-bearer"
  @token_url "https://auth.test/oauth/token"

  defmodule Trust do
    @behaviour Gatekeep.Enterprise

    @impl true
    def trusted_issuer("https://idp.test", _claims, _client), do: {:ok, %{tenant: "acme"}}
    def trusted_issuer("https://down-idp.test", _claims, _client), do: {:ok, %{tenant: "down"}}

    def trusted_issuer("https://static-idp.test", _claims, _client),
      do: {:ok, %{tenant: "static", jwks: :persistent_term.get({__MODULE__, :jwks})}}

    def trusted_issuer(_iss, _claims, _client), do: :error

    @impl true
    def resolve_subject(%{"sub" => "denied"}, _issuer), do: {:error, :access_denied}
    def resolve_subject(%{"sub" => "no-scopes"}, _issuer), do: {:ok, subject: "x", scopes: []}

    def resolve_subject(%{"iss" => iss, "sub" => sub} = claims, issuer),
      do:
        {:ok,
         subject: "#{issuer.tenant}:#{sub}", claims: %{"email" => claims["email"], "iss" => iss}}
  end

  setup do
    TestAuth.put_config(enterprise: [module: Trust])
    key = TestClient.ec_key("idp-1")

    Gatekeep.TestFetcher.put(@idp <> "/.well-known/openid-configuration", %{
      "issuer" => @idp,
      "jwks_uri" => @idp <> "/jwks"
    })

    Gatekeep.TestFetcher.put(@idp <> "/jwks", %{"keys" => [key.public]})
    %{client: TestClient.new(), idp_key: key}
  end

  defp id_jag(client, key, overrides \\ %{}, header \\ %{}) do
    now = TestClient.now()

    claims =
      %{
        "iss" => @idp,
        "sub" => "U123",
        "email" => "pat@acme.example",
        "aud" => TestAuth.issuer(),
        "client_id" => client.client_id,
        "resource" => TestAuth.mcp(),
        "scope" => "notes:read notes:write",
        "iat" => now,
        "exp" => now + 120,
        "jti" => TestClient.random_id()
      }
      |> Map.merge(overrides)
      |> Map.reject(fn {_k, v} -> v == :drop end)

    Gatekeep.JOSE.sign(
      Map.merge(%{"typ" => "oauth-id-jag+jwt", "kid" => key.kid}, header),
      claims,
      key
    )
  end

  defp exchange_jag(client, assertion, extra \\ %{}, headers \\ []) do
    post_form(
      "/oauth/token",
      TestClient.client_auth(client)
      |> Map.merge(%{"grant_type" => @jwt_bearer, "assertion" => assertion})
      |> Map.merge(extra),
      headers
    )
  end

  defp error(conn), do: {conn.status, json_body(conn)["error"]}

  test "the metadata advertises the jwt-bearer grant and the id-jag profile" do
    as = json_body(get_path("/.well-known/oauth-authorization-server"))
    assert @jwt_bearer in as["grant_types_supported"]

    assert as["authorization_grant_profiles_supported"] == [
             "urn:ietf:params:oauth:grant-profile:id-jag"
           ]
  end

  test "a valid ID-JAG gets an access token for the claimed resource, with no refresh token", ctx do
    conn = exchange_jag(ctx.client, id_jag(ctx.client, ctx.idp_key, %{"scope" => "notes:read"}))
    assert conn.status == 200
    body = json_body(conn)
    assert body["scope"] == "notes:read"
    assert body["token_type"] == "Bearer"
    refute Map.has_key?(body, "refresh_token")

    assert get_path("/mcp", bearer(body["access_token"])).resp_body == "hello acme:U123"
    assert get_path("/other", bearer(body["access_token"])).status == 401
  end

  test "the same assertion presented twice is refused", ctx do
    jag = id_jag(ctx.client, ctx.idp_key)
    assert exchange_jag(ctx.client, jag).status == 200
    assert error(exchange_jag(ctx.client, jag)) == {400, "invalid_grant"}
  end

  test "each validation rule refuses with invalid_grant", ctx do
    other_key = TestClient.ec_key("idp-1")
    now = TestClient.now()

    for {label, jag} <- [
          wrong_typ: id_jag(ctx.client, ctx.idp_key, %{}, %{"typ" => "JWT"}),
          id_token_typ: id_jag(ctx.client, ctx.idp_key, %{}, %{"typ" => "id_token+jwt"}),
          wrong_aud: id_jag(ctx.client, ctx.idp_key, %{"aud" => "https://elsewhere.test"}),
          two_auds:
            id_jag(ctx.client, ctx.idp_key, %{"aud" => [TestAuth.issuer(), "https://x.test"]}),
          resource_as_aud: id_jag(ctx.client, ctx.idp_key, %{"aud" => TestAuth.mcp()}),
          other_client:
            id_jag(ctx.client, ctx.idp_key, %{"client_id" => "https://someone.example/c.json"}),
          no_sub: id_jag(ctx.client, ctx.idp_key, %{"sub" => :drop}),
          expired: id_jag(ctx.client, ctx.idp_key, %{"iat" => now - 300, "exp" => now - 31}),
          future: id_jag(ctx.client, ctx.idp_key, %{"iat" => now + 120, "exp" => now + 200}),
          not_yet: id_jag(ctx.client, ctx.idp_key, %{"nbf" => now + 120}),
          too_long: id_jag(ctx.client, ctx.idp_key, %{"exp" => now + 3600}),
          no_jti: id_jag(ctx.client, ctx.idp_key, %{"jti" => :drop}),
          untrusted_iss: id_jag(ctx.client, ctx.idp_key, %{"iss" => "https://evil-idp.test"}),
          prefix_iss: id_jag(ctx.client, ctx.idp_key, %{"iss" => "https://idp.test/evil"}),
          forged_signature: id_jag(ctx.client, other_key),
          unknown_resource:
            id_jag(ctx.client, ctx.idp_key, %{"resource" => "https://elsewhere.test/mcp"}),
          unsupported_cnf: id_jag(ctx.client, ctx.idp_key, %{"cnf" => %{"x5t#S256" => "abc"}}),
          garbage: "not.a.jwt"
        ] do
      assert error(exchange_jag(ctx.client, jag)) == {400, "invalid_grant"}, "#{label} was accepted"
    end
  end

  test "an assertion with a key in its header is not verified with that key", ctx do
    attacker = TestClient.ec_key("attacker")

    jag =
      id_jag(ctx.client, attacker, %{}, %{
        "jwk" => attacker.public,
        "jku" => "https://evil.test/jwks"
      })

    assert error(exchange_jag(ctx.client, jag)) == {400, "invalid_grant"}
  end

  test "RS256 is accepted and PS384 and HS256 are not", ctx do
    rsa = TestClient.rsa_key("idp-rsa")
    Gatekeep.TestFetcher.put(@idp <> "/jwks", %{"keys" => [ctx.idp_key.public, rsa.public]})
    assert exchange_jag(ctx.client, id_jag(ctx.client, rsa)).status == 200

    ps = TestClient.rsa_key("idp-rsa", "PS384")
    Gatekeep.TestFetcher.put(@idp <> "/jwks", %{"keys" => [ps.public]})
    Gatekeep.Cache.delete(TestAuth, {:enterprise_jwks, @idp})
    assert error(exchange_jag(ctx.client, id_jag(ctx.client, ps))) == {400, "invalid_grant"}
  end

  test "a discovery document naming another issuer is refused", ctx do
    Gatekeep.TestFetcher.put(@idp <> "/.well-known/openid-configuration", %{
      "issuer" => "https://other.test",
      "jwks_uri" => @idp <> "/jwks"
    })

    assert error(exchange_jag(ctx.client, id_jag(ctx.client, ctx.idp_key))) ==
             {400, "invalid_grant"}
  end

  test "an issuer with configured keys needs no discovery", ctx do
    key = TestClient.ec_key("static-1")
    :persistent_term.put({Trust, :jwks}, [key.public])
    jag = id_jag(ctx.client, key, %{"iss" => "https://static-idp.test"})

    assert get_path("/mcp", bearer(json_body(exchange_jag(ctx.client, jag))["access_token"])).resp_body ==
             "hello static:U123"
  end

  test "a user the app doesn't know is access_denied", ctx do
    assert error(exchange_jag(ctx.client, id_jag(ctx.client, ctx.idp_key, %{"sub" => "denied"}))) ==
             {400, "access_denied"}
  end

  test "an app narrowing to no scopes refuses the token instead of granting all", ctx do
    jag = id_jag(ctx.client, ctx.idp_key, %{"sub" => "no-scopes"})
    assert error(exchange_jag(ctx.client, jag)) == {400, "access_denied"}
  end

  test "an unreachable issuer's key set is fetched once per cooldown, not per request", ctx do
    idp = "https://down-idp.test"

    for _ <- 1..3 do
      jag = id_jag(ctx.client, ctx.idp_key, %{"iss" => idp})
      assert error(exchange_jag(ctx.client, jag)) == {400, "invalid_grant"}
    end

    assert Gatekeep.TestFetcher.count(idp <> "/.well-known/openid-configuration") == 1
  end

  test "a cache full of clients doesn't make an issuer's keys refetch per request", ctx do
    TestAuth.put_config(enterprise: [module: Trust], client_cache_size: 2)
    for _ <- 1..3, do: Gatekeep.Clients.fetch(TestAuth.config(), TestClient.new().client_id)
    discovery = @idp <> "/.well-known/openid-configuration"
    before = Gatekeep.TestFetcher.count(discovery)

    for _ <- 1..3 do
      jag = id_jag(ctx.client, ctx.idp_key)
      assert exchange_jag(ctx.client, jag).status == 200
    end

    assert Gatekeep.TestFetcher.count(discovery) - before == 1
  end

  test "an issuer whose cooldown can't be kept is not fetched", ctx do
    TestAuth.put_config(enterprise: [module: Trust], client_cache_size: 1)
    discovery = @idp <> "/.well-known/openid-configuration"
    before = Gatekeep.TestFetcher.count(discovery)
    Gatekeep.Cache.put(TestAuth, {:enterprise_jwks, "https://other.test"}, [], 600, 1)
    jag = id_jag(ctx.client, ctx.idp_key)
    assert error(exchange_jag(ctx.client, jag)) == {400, "invalid_grant"}
    assert Gatekeep.TestFetcher.count(discovery) == before
  end

  test "scopes: the claim's, narrowed by the request, never widened", ctx do
    jag = id_jag(ctx.client, ctx.idp_key, %{"scope" => "notes:read"})

    assert error(exchange_jag(ctx.client, jag, %{"scope" => "notes:write"})) ==
             {400, "invalid_scope"}

    jag = id_jag(ctx.client, ctx.idp_key)

    assert json_body(exchange_jag(ctx.client, jag, %{"scope" => "notes:write"}))["scope"] ==
             "notes:write"
  end

  test "the resource parameter must match the claim; without a claim the default is used", ctx do
    jag = id_jag(ctx.client, ctx.idp_key)

    assert error(exchange_jag(ctx.client, jag, %{"resource" => TestAuth.other()})) ==
             {400, "invalid_target"}

    jag = id_jag(ctx.client, ctx.idp_key, %{"resource" => :drop, "scope" => :drop})
    assert json_body(exchange_jag(ctx.client, jag))["scope"] == "notes:read notes:write"
  end

  test "require_resource_claim refuses an assertion without one", ctx do
    TestAuth.put_config(enterprise: [module: Trust, require_resource_claim: true])
    jag = id_jag(ctx.client, ctx.idp_key, %{"resource" => :drop})
    assert error(exchange_jag(ctx.client, jag)) == {400, "invalid_grant"}
  end

  test "a cnf-bound assertion needs a DPoP proof from that key", ctx do
    key = TestClient.ec_key(nil)
    thief = TestClient.ec_key(nil)
    bound = fn -> id_jag(ctx.client, ctx.idp_key, %{"cnf" => %{"jkt" => TestClient.jkt(key)}}) end
    proof = &{"dpop", TestClient.dpop_proof(&1, "POST", @token_url)}

    assert error(exchange_jag(ctx.client, bound.())) == {400, "invalid_grant"}
    assert error(exchange_jag(ctx.client, bound.(), %{}, [proof.(thief)])) == {400, "invalid_grant"}

    body = json_body(exchange_jag(ctx.client, bound.(), %{}, [proof.(key)]))
    assert body["token_type"] == "DPoP"
  end

  test "an issuer that isn't configured for enterprise refuses the grant", ctx do
    TestAuth.put_config()

    assert error(exchange_jag(ctx.client, id_jag(ctx.client, ctx.idp_key))) ==
             {400, "unsupported_grant_type"}
  end

  test "a public client presenting someone else's assertion is caught by client_id", ctx do
    public = TestClient.new(public: true)
    jag = id_jag(ctx.client, ctx.idp_key)

    conn =
      post_form("/oauth/token", %{
        "grant_type" => @jwt_bearer,
        "assertion" => jag,
        "client_id" => public.client_id
      })

    assert error(conn) == {400, "invalid_grant"}
  end
end
