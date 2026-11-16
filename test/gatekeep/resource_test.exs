defmodule Gatekeep.ResourceTest do
  use Gatekeep.Case

  @token_url "https://auth.test/oauth/token"
  @mcp_url "https://mcp.test/mcp"

  setup do
    %{client: TestClient.new()}
  end

  defp challenge(conn), do: conn |> Plug.Conn.get_resp_header("www-authenticate") |> List.first()

  defp dpop_header(key, method, url, opts \\ []),
    do: {"dpop", TestClient.dpop_proof(key, method, url, opts)}

  describe "access tokens at a resource" do
    test "an expired token is refused with invalid_token", %{client: client} do
      %{"access_token" => access} = sign_in(client)

      Gatekeep.TestRepo.update_all(Gatekeep.Storage.Ecto.AccessToken,
        set: [expires_at: ~U[2020-01-01 00:00:00Z]]
      )

      conn = get_path("/mcp", bearer(access))
      assert conn.status == 401
      assert challenge(conn) =~ ~s(error="invalid_token")
    end

    test "a token issued for one resource is refused by another", %{client: client} do
      %{"access_token" => mcp} = sign_in(client)

      %{"access_token" => other} =
        sign_in(client, %{"resource" => TestAuth.other(), "scope" => nil})

      assert get_path("/other", bearer(mcp)).status == 401
      assert get_path("/mcp", bearer(other)).status == 401
      assert get_path("/other", bearer(other)).status == 200
    end

    test "a token without a needed scope gets 403 insufficient_scope naming it", %{client: client} do
      %{"access_token" => access} = sign_in(client, %{"scope" => "notes:read"})
      assert get_path("/mcp?need=notes:read", bearer(access)).status == 200
      conn = get_path("/mcp?need=notes:write", bearer(access))
      assert conn.status == 403

      assert challenge(conn) =~
               ~s(Bearer resource_metadata="https://mcp.test/.well-known/oauth-protected-resource/mcp", error="insufficient_scope", scope="notes:write")
    end

    test "no token gets a challenge naming the needed scope and no error code" do
      conn = get_path("/mcp?need=notes:read")
      assert conn.status == 401
      assert challenge(conn) =~ ~s(scope="notes:read")
      refute challenge(conn) =~ "error="
    end

    test "garbage and unknown schemes are refused", %{client: client} do
      %{"access_token" => access} = sign_in(client)
      assert get_path("/mcp", [{"authorization", "Basic " <> access}]).status == 401
      assert get_path("/mcp", bearer(access <> "x")).status == 401
      assert get_path("/mcp", [{"authorization", "bearer " <> access}]).status == 200
    end

    test "blocking the client stops its tokens at once", %{client: client} do
      %{"access_token" => access} = sign_in(client)
      TestAuth.put_config(blocked_clients: [client.client_id])
      assert get_path("/mcp", bearer(access)).status == 401
    end
  end

  describe "DPoP" do
    setup do
      %{key: TestClient.ec_key(nil)}
    end

    defp dpop_sign_in(client, key, extra \\ %{}) do
      {code, verifier, _} = authorize(client, extra)
      exchange(client, code, verifier, %{}, [dpop_header(key, "POST", @token_url)])
    end

    test "binds the tokens to the proof key and needs that key at the resource", %{
      client: client,
      key: key
    } do
      body = json_body(dpop_sign_in(client, key))
      assert body["token_type"] == "DPoP"
      access = body["access_token"]

      ok = [
        {"authorization", "DPoP " <> access},
        dpop_header(key, "GET", @mcp_url, access_token: access)
      ]

      assert get_path("/mcp", ok).status == 200

      # The stolen token alone, as Bearer.
      conn = get_path("/mcp", bearer(access))
      assert conn.status == 401
      assert challenge(conn) =~ ~s(error="invalid_token")

      # Another key's valid proof: the key binding is wrong, so the token
      # is (RFC 9449 §7.1, Figure 16).
      thief = TestClient.ec_key(nil)

      conn =
        get_path("/mcp", [
          {"authorization", "DPoP " <> access},
          dpop_header(thief, "GET", @mcp_url, access_token: access)
        ])

      assert conn.status == 401

      assert challenge(conn) =~
               ~s(DPoP resource_metadata="https://mcp.test/.well-known/oauth-protected-resource/mcp", error="invalid_token")

      # A proof for another request, one without ath, and a replay.
      for proof <- [
            dpop_header(key, "POST", @mcp_url, access_token: access),
            dpop_header(key, "GET", "https://mcp.test/other", access_token: access),
            dpop_header(key, "GET", @mcp_url),
            dpop_header(key, "GET", @mcp_url, access_token: "another")
          ] do
        assert get_path("/mcp", [{"authorization", "DPoP " <> access}, proof]).status == 401
      end

      replayed = dpop_header(key, "GET", @mcp_url, access_token: access)
      assert get_path("/mcp", [{"authorization", "DPoP " <> access}, replayed]).status == 200
      assert get_path("/mcp", [{"authorization", "DPoP " <> access}, replayed]).status == 401
    end

    test "a Bearer token presented as DPoP is refused", %{client: client, key: key} do
      %{"access_token" => access} = sign_in(client)

      conn =
        get_path("/mcp", [
          {"authorization", "DPoP " <> access},
          dpop_header(key, "GET", @mcp_url, access_token: access)
        ])

      assert conn.status == 401
    end

    test "a bound refresh token needs a proof from the same key", %{client: client, key: key} do
      %{"refresh_token" => r1} = json_body(dpop_sign_in(client, key))

      assert {400, "invalid_grant"} =
               {refresh(client, r1).status, json_body(refresh(client, r1))["error"]}

      thief = TestClient.ec_key(nil)
      assert refresh(client, r1, %{}, [dpop_header(thief, "POST", @token_url)]).status == 400

      conn = refresh(client, r1, %{}, [dpop_header(key, "POST", @token_url)])
      assert conn.status == 200
      assert json_body(conn)["token_type"] == "DPoP"
    end

    test "a code bound with dpop_jkt needs a proof from that key", %{client: client, key: key} do
      thief = TestClient.ec_key(nil)
      {code, verifier, _} = authorize(client, %{"dpop_jkt" => TestClient.jkt(key)})
      conn = exchange(client, code, verifier, %{}, [dpop_header(thief, "POST", @token_url)])
      assert {conn.status, json_body(conn)["error"]} == {400, "invalid_grant"}

      {code, verifier, _} = authorize(client, %{"dpop_jkt" => TestClient.jkt(key)})
      assert exchange(client, code, verifier).status == 400

      {code, verifier, _} = authorize(client, %{"dpop_jkt" => TestClient.jkt(key)})

      assert exchange(client, code, verifier, %{}, [dpop_header(key, "POST", @token_url)]).status ==
               200
    end

    test "a bad proof is invalid_dpop_proof and leaves the code usable", %{client: client, key: key} do
      {code, verifier, _} = authorize(client)

      conn =
        exchange(client, code, verifier, %{}, [
          dpop_header(key, "POST", "https://auth.test/elsewhere")
        ])

      assert {conn.status, json_body(conn)["error"]} == {400, "invalid_dpop_proof"}

      assert exchange(client, code, verifier, %{}, [dpop_header(key, "POST", @token_url)]).status ==
               200
    end

    test "a client declaring dpop_bound_access_tokens never gets Bearer tokens", %{key: key} do
      client = TestClient.new(metadata: %{"dpop_bound_access_tokens" => true})
      {code, verifier, _} = authorize(client)
      conn = exchange(client, code, verifier)
      assert {conn.status, json_body(conn)["error"]} == {400, "invalid_dpop_proof"}

      assert json_body(
               exchange(client, code, verifier, %{}, [dpop_header(key, "POST", @token_url)])
             )["token_type"] == "DPoP"
    end

    @tag config: [
           resources: [[id: "https://mcp.test/mcp", scopes: ["notes:read"], dpop: :required]]
         ]
    test "a resource with dpop: :required issues and accepts only bound tokens", %{
      client: client,
      key: key
    } do
      {code, verifier, _} = authorize(client)
      conn = exchange(client, code, verifier)
      assert json_body(conn)["error"] == "invalid_dpop_proof"
      assert json_body(dpop_sign_in(client, key))["token_type"] == "DPoP"

      conn = get_path("/mcp")
      refute challenge(conn) =~ "Bearer"

      assert json_body(get_path("/.well-known/oauth-protected-resource/mcp"))[
               "dpop_bound_access_tokens_required"
             ]
    end
  end
end
