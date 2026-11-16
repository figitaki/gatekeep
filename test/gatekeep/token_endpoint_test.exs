defmodule Gatekeep.TokenEndpointTest do
  use Gatekeep.Case

  setup do
    %{client: TestClient.new()}
  end

  defp error(conn), do: {conn.status, json_body(conn)["error"]}

  describe "authorization codes" do
    test "a wrong PKCE verifier is refused, and uses the code up", %{client: client} do
      {code, verifier, _} = authorize(client)
      {other, _} = TestClient.pkce()
      assert error(exchange(client, code, other)) == {400, "invalid_grant"}
      assert error(exchange(client, code, verifier)) == {400, "invalid_grant"}
    end

    test "a missing or malformed verifier is refused", %{client: client} do
      {code, verifier, _} = authorize(client)
      assert error(exchange(client, code, nil |> to_string())) == {400, "invalid_grant"}
      {code, _, _} = authorize(client)
      assert error(exchange(client, code, verifier <> " ")) == {400, "invalid_grant"}
    end

    test "replaying a code is refused and revokes the tokens the first use got", %{client: client} do
      {code, verifier, _} = authorize(client)

      %{"access_token" => access, "refresh_token" => refresh} =
        json_body(exchange(client, code, verifier))

      assert get_path("/mcp", bearer(access)).status == 200

      assert error(exchange(client, code, verifier)) == {400, "invalid_grant"}
      assert get_path("/mcp", bearer(access)).status == 401
      assert error(refresh(client, refresh)) == {400, "invalid_grant"}
    end

    test "another client replaying a code changes nothing", %{client: client} do
      {code, verifier, _} = authorize(client)
      %{"access_token" => access} = json_body(exchange(client, code, verifier))
      thief = TestClient.new()

      assert error(exchange(thief, code, verifier, %{"redirect_uri" => client.redirect_uri})) ==
               {400, "invalid_grant"}

      assert get_path("/mcp", bearer(access)).status == 200
    end

    test "an expired code is refused", %{client: client} do
      {code, verifier, _} = authorize(client)

      Gatekeep.TestRepo.update_all(Gatekeep.Storage.Ecto.Code,
        set: [expires_at: ~U[2020-01-01 00:00:00Z]]
      )

      assert error(exchange(client, code, verifier)) == {400, "invalid_grant"}
    end

    test "a code redeemed by another client, or at another redirect URI", %{client: client} do
      {code, verifier, _} = authorize(client)
      assert error(exchange(TestClient.new(), code, verifier)) == {400, "invalid_grant"}

      {code, verifier, _} = authorize(client)

      assert error(
               exchange(client, code, verifier, %{"redirect_uri" => "http://127.0.0.1/callback"})
             ) ==
               {400, "invalid_grant"}
    end

    test "another client sharing the redirect URI can't redeem the code", %{client: client} do
      loopback = "http://127.0.0.1/callback"
      {code, verifier, _} = authorize(client, %{"redirect_uri" => loopback})
      thief = TestClient.new()
      conn = exchange(thief, code, verifier, %{"redirect_uri" => loopback})
      assert {conn.status, json_body(conn)["error"]} == {400, "invalid_grant"}
    end

    test "naming another resource at the token endpoint is invalid_target", %{client: client} do
      {code, verifier, _} = authorize(client)

      assert error(exchange(client, code, verifier, %{"resource" => TestAuth.other()})) ==
               {400, "invalid_target"}
    end

    test "two concurrent redemptions: exactly one succeeds", %{client: client} do
      {code, verifier, _} = authorize(client)

      statuses =
        1..2
        |> Enum.map(fn _ -> Task.async(fn -> exchange(client, code, verifier).status end) end)
        |> Enum.map(&Task.await/1)
        |> Enum.sort()

      assert statuses == [200, 400]
    end

    test "an unknown grant type, and a parameter given twice", %{client: client} do
      conn =
        post_form("/oauth/token", Map.put(TestClient.client_auth(client), "grant_type", "password"))

      assert error(conn) == {400, "unsupported_grant_type"}

      body =
        URI.encode_query(TestClient.client_auth(client)) <>
          "&grant_type=refresh_token&grant_type=authorization_code"

      conn =
        Plug.Test.conn(:post, "/oauth/token", body)
        |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
        |> call()

      assert error(conn) == {400, "invalid_request"}
    end

    test "codes and tokens are stored only as hashes", %{client: client} do
      %{"access_token" => access, "refresh_token" => refresh} = sign_in(client)

      dump =
        :erlang.term_to_binary(
          Gatekeep.TestRepo.query!(
            "select * from gatekeep_access_tokens union all select * from gatekeep_access_tokens"
          ).rows
        )

      grants =
        :erlang.term_to_binary(Gatekeep.TestRepo.query!("select * from gatekeep_grants").rows)

      refute :binary.match(dump, access) != :nomatch
      refute :binary.match(grants, refresh) != :nomatch
    end
  end

  describe "refresh tokens" do
    test "rotate, and presenting a replaced one revokes the grant", %{client: client} do
      %{"refresh_token" => r1} = sign_in(client)
      %{"refresh_token" => r2, "access_token" => a2} = json_body(refresh(client, r1))
      assert r2 != r1
      assert get_path("/mcp", bearer(a2)).status == 200

      assert error(refresh(client, r1)) == {400, "invalid_grant"}
      assert get_path("/mcp", bearer(a2)).status == 401
      assert error(refresh(client, r2)) == {400, "invalid_grant"}
    end

    test "presenting any earlier one revokes the grant, not only the last", %{client: client} do
      %{"refresh_token" => r1} = sign_in(client)
      %{"refresh_token" => r2} = json_body(refresh(client, r1))
      %{"refresh_token" => r3} = json_body(refresh(client, r2))
      assert error(refresh(client, r1)) == {400, "invalid_grant"}
      assert error(refresh(client, r3)) == {400, "invalid_grant"}
    end

    test "another client presenting a replaced one changes nothing", %{client: client} do
      %{"refresh_token" => r1} = sign_in(client)
      %{"refresh_token" => r2} = json_body(refresh(client, r1))
      assert error(refresh(TestClient.new(), r1)) == {400, "invalid_grant"}
      assert error(refresh(TestClient.new(), r2)) == {400, "invalid_grant"}
      assert refresh(client, r2).status == 200
    end

    test "don't rotate for a resource that doesn't ask for it", %{client: client} do
      %{"refresh_token" => r1} = sign_in(client, %{"resource" => TestAuth.other(), "scope" => nil})
      body = json_body(refresh(client, r1))
      refute Map.has_key?(body, "refresh_token")
      assert refresh(client, r1).status == 200
    end

    test "can narrow scopes but never widen them", %{client: client} do
      %{"refresh_token" => r1} = sign_in(client, %{"scope" => "notes:read"})

      assert error(refresh(client, r1, %{"scope" => "notes:read notes:write"})) ==
               {400, "invalid_scope"}

      %{"refresh_token" => r2} = sign_in(client)
      assert %{"scope" => "notes:read"} = json_body(refresh(client, r2, %{"scope" => "notes:read"}))
    end

    test "can't be moved to another resource", %{client: client} do
      %{"refresh_token" => r1} = sign_in(client)

      assert error(refresh(client, r1, %{"resource" => TestAuth.other()})) ==
               {400, "invalid_target"}
    end

    test "issue nothing once the grant expires or the resource is off", %{client: client} do
      %{"refresh_token" => r1} = sign_in(client)

      Gatekeep.TestRepo.update_all(Gatekeep.Storage.Ecto.Grant,
        set: [expires_at: ~U[2020-01-01 00:00:00Z]]
      )

      assert error(refresh(client, r1)) == {400, "invalid_grant"}

      Gatekeep.TestRepo.update_all(Gatekeep.Storage.Ecto.Grant, set: [expires_at: nil])

      TestAuth.put_config(
        resources: [[id: TestAuth.mcp(), scopes: ["notes:read"], enabled: false]],
        default_resource: nil
      )

      assert error(refresh(client, r1)) == {400, "invalid_grant"}
    end
  end

  describe "client authentication" do
    test "accepts ES256 and RS256 assertions addressed to the issuer", %{client: client} do
      config = TestAuth.config()

      assert {:ok, _} =
               Gatekeep.ClientAuth.verify_client_assertion(config, TestClient.client_auth(client))

      assert {:ok, _} =
               Gatekeep.ClientAuth.verify_client_assertion(
                 config,
                 TestClient.client_auth(client, rsa: true)
               )
    end

    test "refuses the token endpoint, a list, or another server as the audience", %{client: client} do
      config = TestAuth.config()

      for aud <- ["https://auth.test/oauth/token", ["https://auth.test"], "https://other.test"] do
        assert Gatekeep.ClientAuth.verify_client_assertion(
                 config,
                 TestClient.client_auth(client, aud: aud)
               ) ==
                 {:error, :wrong_audience}
      end

      config = %{config | token_endpoint_audience_clients: [client.client_id]}

      assert {:ok, _} =
               Gatekeep.ClientAuth.verify_client_assertion(
                 config,
                 TestClient.client_auth(client, aud: "https://auth.test/oauth/token")
               )
    end

    test "refuses expired, long-lived, future, and replayed assertions", %{client: client} do
      config = TestAuth.config()
      now = TestClient.now()

      check =
        &Gatekeep.ClientAuth.verify_client_assertion(config, TestClient.client_auth(client, &1))

      assert check.(iat: now - 400, exp: now - 31) == {:error, :expired}
      assert check.(iat: now, exp: now + 301) == {:error, :assertion_too_long}
      assert check.(iat: now + 60, exp: now + 120) == {:error, :issued_in_future}
      assert check.(nbf: now + 60) == {:error, :not_yet_valid}
      assert {:ok, _} = check.(nbf: now + 30)

      params = TestClient.client_auth(client)
      assert {:ok, _} = Gatekeep.ClientAuth.verify_client_assertion(config, params)
      assert Gatekeep.ClientAuth.verify_client_assertion(config, params) == {:error, :replayed}
    end

    test "refuses an assertion signed by another client's key, or naming another client", %{
      client: client
    } do
      config = TestAuth.config()
      other = TestClient.new()

      assert Gatekeep.ClientAuth.verify_client_assertion(
               config,
               TestClient.client_auth(client, key: %{other.root | kid: client.root.kid})
             ) ==
               {:error, :bad_signature}

      assert Gatekeep.ClientAuth.verify_client_assertion(
               config,
               Map.put(TestClient.client_auth(client), "client_id", other.client_id)
             ) == {:error, :client_id_mismatch}

      conn = exchange(client, "x", "y", TestClient.client_auth(client, key: other.root))
      assert error(conn) == {401, "invalid_client"}
    end

    test "a key removed from jwks_uri stops verifying once the cache is refreshed", %{
      client: client
    } do
      config = TestAuth.config()

      assert {:ok, _} =
               Gatekeep.ClientAuth.verify_client_assertion(config, TestClient.client_auth(client))

      TestClient.publish(client, %{}, [client.rsa.public])
      Gatekeep.Clients.forget(config, client.client_id)

      assert Gatekeep.ClientAuth.verify_client_assertion(config, TestClient.client_auth(client)) ==
               {:error, :bad_signature}
    end

    test "a client with keys can't sign in as a public client", %{client: client} do
      {code, verifier, _} = authorize(client)

      conn =
        post_form("/oauth/token", %{
          "grant_type" => "authorization_code",
          "client_id" => client.client_id,
          "code" => code,
          "code_verifier" => verifier,
          "redirect_uri" => client.redirect_uri
        })

      assert error(conn) == {401, "invalid_client"}
    end

    @tag config: [
           clients: [
             [
               client_id: "web",
               client_secret_sha256: Gatekeep.hash_client_secret("s3cret"),
               redirect_uris: ["https://web.example/cb"]
             ]
           ]
         ]
    test "the Basic scheme is case-insensitive" do
      config = TestAuth.config()

      for scheme <- ["Basic", "basic", "BASIC"] do
        header = scheme <> " " <> Base.encode64("web:s3cret")

        assert {:ok, %{client_id: "web"}, "client_secret_basic"} =
                 Gatekeep.ClientAuth.authenticate(config, %{}, header)
      end

      assert Gatekeep.ClientAuth.authenticate(config, %{}, "basic " <> Base.encode64("web:no")) ==
               {:error, :bad_secret}
    end

    test "concurrent requests for one client share one metadata fetch" do
      client = TestClient.new()
      config = TestAuth.config()

      1..8
      |> Enum.map(fn _ ->
        Task.async(fn -> Gatekeep.Clients.fetch(config, client.client_id) end)
      end)
      |> Enum.each(&assert({:ok, _} = Task.await(&1)))

      assert Gatekeep.TestFetcher.count(client.client_id) == 1
    end

    @tag config: [client_cache_size: 2]
    test "a full cache stops caching instead of growing" do
      config = TestAuth.config()
      for _ <- 1..4, do: Gatekeep.Clients.fetch(config, TestClient.new().client_id)
      assert :ets.info(Gatekeep.Cache.table(TestAuth), :size) == 2
    end

    test "a metadata document whose client_id doesn't match its URL is refused" do
      client = TestClient.new(metadata: %{"client_id" => "https://other.example/client.json"})

      assert Gatekeep.Clients.fetch(TestAuth.config(), client.client_id) ==
               {:error, :invalid_client_metadata}
    end
  end

  describe "revocation" do
    test "revoking the refresh token ends the grant and its access tokens", %{client: client} do
      %{"access_token" => access, "refresh_token" => refresh} = sign_in(client)
      conn = post_form("/oauth/revoke", Map.put(TestClient.client_auth(client), "token", refresh))
      assert conn.status == 200
      assert get_path("/mcp", bearer(access)).status == 401
      assert error(refresh(client, refresh)) == {400, "invalid_grant"}
    end

    test "revoking an access token ends only that token", %{client: client} do
      %{"access_token" => access, "refresh_token" => refresh} = sign_in(client)

      assert post_form("/oauth/revoke", Map.put(TestClient.client_auth(client), "token", access)).status ==
               200

      assert get_path("/mcp", bearer(access)).status == 401
      assert refresh(client, refresh).status == 200
    end

    test "another client's tokens and unknown tokens succeed without effect", %{client: client} do
      %{"access_token" => access, "refresh_token" => refresh} = sign_in(client)
      thief = TestClient.new()

      for token <- [access, refresh, "unknown"] do
        assert post_form("/oauth/revoke", Map.put(TestClient.client_auth(thief), "token", token)).status ==
                 200
      end

      assert get_path("/mcp", bearer(access)).status == 200
      assert refresh(client, refresh).status == 200
    end

    test "an unauthenticated revocation is invalid_client", %{client: client} do
      %{"refresh_token" => refresh} = sign_in(client)
      assert error(post_form("/oauth/revoke", %{"token" => refresh})) == {401, "invalid_client"}
    end

    test "Gatekeep.revoke_grant/2 ends a grant for settings pages", %{client: client} do
      %{"access_token" => access} = sign_in(client, %{}, subject: "agent:7", owner: "user:1")
      assert [%{id: id, subject: "agent:7"}] = TestAuth.list_grants(owner: "user:1")
      :ok = TestAuth.revoke_grant(id)
      assert get_path("/mcp", bearer(access)).status == 401
    end
  end
end
