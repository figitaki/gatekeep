defmodule Gatekeep.AuthorizationTest do
  use Gatekeep.Case

  describe "discovery" do
    test "the challenge leads to resource metadata, which leads to the issuer's metadata" do
      conn = get_path("/mcp")
      assert conn.status == 401
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")

      assert challenge =~
               ~s(Bearer resource_metadata="https://mcp.test/.well-known/oauth-protected-resource/mcp")

      assert challenge =~ ~s(DPoP resource_metadata=)
      refute challenge =~ "error="

      prm = json_body(get_path("/.well-known/oauth-protected-resource/mcp"))
      assert prm["resource"] == TestAuth.mcp()
      assert prm["authorization_servers"] == [TestAuth.issuer()]
      assert prm["scopes_supported"] == ["notes:read", "notes:write"]
      assert prm["resource_name"] == "Test MCP"

      as = json_body(get_path("/.well-known/oauth-authorization-server"))
      assert as["issuer"] == TestAuth.issuer()
      assert as["token_endpoint"] == "https://auth.test/oauth/token"
      assert as["code_challenge_methods_supported"] == ["S256"]
      assert as["authorization_response_iss_parameter_supported"]
      assert as["client_id_metadata_document_supported"]
      assert as["registration_endpoint"] == "https://auth.test/oauth/register"
    end

    @tag config: [
           resources: [[id: "https://mcp.test/mcp", client_auth_methods: ["private_key_jwt"]]]
         ]
    test "with no resource taking public clients, there is no registration endpoint" do
      as = json_body(get_path("/.well-known/oauth-authorization-server"))
      refute Map.has_key?(as, "registration_endpoint")
      assert as["token_endpoint_auth_methods_supported"] == ["private_key_jwt"]

      conn = post_json("/oauth/register", %{"redirect_uris" => ["https://x.example/cb"]})
      assert conn.status == 404
    end
  end

  describe "a valid request" do
    test "reaches consent with the verified domain, resource, and scopes" do
      client = TestClient.new()
      {params, _} = authorize_params(client, %{"scope" => "notes:read"})
      conn = get_path("/oauth/authorize?" <> URI.encode_query(params))
      assert conn.status == 200
      assert conn.resp_body == "consent for " <> URI.parse(client.client_id).host
      assert Plug.Conn.get_resp_header(conn, "x-frame-options") == ["DENY"]
      assert_received {:consent, request}
      assert request.resource.id == TestAuth.mcp()
      assert request.scopes == ["notes:read"]
      assert request.scope_descriptions == %{"notes:read" => "Read notes"}
    end

    test "approval redirects with the code, state, and iss" do
      client = TestClient.new()
      {_code, _verifier, _} = authorize(client)
      {params, _} = authorize_params(client)
      {:ok, request} = Gatekeep.Authorization.check(TestAuth.config(), params)
      {:ok, url} = Gatekeep.Authorization.approve(TestAuth.config(), request, subject: "u")
      uri = URI.parse(url)
      assert "#{uri.scheme}://#{uri.host}#{uri.path}" == client.redirect_uri
      query = URI.decode_query(uri.query)
      assert query["state"] == "xyz"
      assert query["iss"] == TestAuth.issuer()
      assert String.starts_with?(query["code"], "gkc_code_")
    end

    test "a loopback redirect URI may use any port (RFC 8252 §7.3)" do
      client = TestClient.new()
      {params, _} = authorize_params(client, %{"redirect_uri" => "http://127.0.0.1:53111/callback"})
      assert {:ok, _} = Gatekeep.Authorization.check(TestAuth.config(), params)
    end

    test "the resource compares without case, default port, or trailing slash" do
      client = TestClient.new()
      {params, _} = authorize_params(client, %{"resource" => "HTTPS://MCP.test:443/mcp/"})

      assert {:ok, %{resource: %{id: "https://mcp.test/mcp"}}} =
               Gatekeep.Authorization.check(TestAuth.config(), params)
    end

    test "denying sends access_denied back with iss" do
      client = TestClient.new()
      {params, _} = authorize_params(client)
      {:ok, request} = Gatekeep.Authorization.check(TestAuth.config(), params)

      query =
        Gatekeep.Authorization.deny(TestAuth.config(), request)
        |> URI.parse()
        |> Map.get(:query)
        |> URI.decode_query()

      assert query == %{"error" => "access_denied", "state" => "xyz", "iss" => TestAuth.issuer()}
    end

    test "approval can narrow scopes but not widen them or grant none" do
      client = TestClient.new()
      {params, _} = authorize_params(client, %{"scope" => "notes:read"})
      {:ok, request} = Gatekeep.Authorization.check(TestAuth.config(), params)
      config = TestAuth.config()

      assert Gatekeep.Authorization.approve(config, request,
               subject: "u",
               scopes: ["notes:read", "notes:write"]
             ) ==
               {:error, :invalid_scopes}

      assert Gatekeep.Authorization.approve(config, request, subject: "u", scopes: []) ==
               {:error, :invalid_scopes}
    end
  end

  describe "open redirects" do
    test "an unregistered redirect URI gets an error page, never a redirect" do
      client = TestClient.new()

      for uri <- [
            "https://evil.example/callback",
            client.redirect_uri <> "/../steal",
            client.redirect_uri <> "?next=https://evil.example",
            "https://" <> URI.parse(client.client_id).host <> ".evil.example/callback",
            "http://127.0.0.1.evil.example/callback",
            nil
          ] do
        {params, _} = authorize_params(client, %{"redirect_uri" => uri})

        conn =
          get_path(
            "/oauth/authorize?" <> URI.encode_query(Map.reject(params, &is_nil(elem(&1, 1))))
          )

        assert conn.status == 400, "#{inspect(uri)} was accepted"
        assert Plug.Conn.get_resp_header(conn, "location") == []
      end
    end

    test "an unknown or invalid client gets an error page, never a redirect" do
      for id <- [
            "https://unknown.example/client.json",
            "http://plain.example/c.json",
            "not-a-url",
            "gkc_nope"
          ] do
        conn =
          get_path(
            "/oauth/authorize?" <>
              URI.encode_query(%{"client_id" => id, "redirect_uri" => "https://x.example/cb"})
          )

        assert conn.status == 400
        assert Plug.Conn.get_resp_header(conn, "location") == []
      end
    end

    test "a metadata document can't list redirect URIs on another host" do
      client = TestClient.new(metadata: %{"redirect_uris" => ["https://evil.example/cb"]})
      {params, _} = authorize_params(client, %{"redirect_uri" => "https://evil.example/cb"})
      assert Gatekeep.Authorization.check(TestAuth.config(), params) == {:error, :invalid_client}
    end

    test "a registered client's bad request is shown here, not redirected" do
      conn = post_json("/oauth/register", %{"redirect_uris" => ["https://anyone.example/cb"]})
      %{"client_id" => client_id} = json_body(conn)

      conn =
        get_path(
          "/oauth/authorize?" <>
            URI.encode_query(%{
              "client_id" => client_id,
              "redirect_uri" => "https://anyone.example/cb",
              "response_type" => "code",
              "scope" => "nope"
            })
        )

      assert conn.status == 400
      assert Plug.Conn.get_resp_header(conn, "location") == []
    end
  end

  describe "rejected requests that redirect with the error and iss" do
    test "no PKCE, plain PKCE, a bad challenge, an unknown scope, another resource, or another response type" do
      client = TestClient.new()

      for {extra, error} <- [
            {%{"code_challenge" => nil}, "invalid_request"},
            {%{"code_challenge_method" => "plain"}, "invalid_request"},
            {%{"code_challenge" => "short"}, "invalid_request"},
            {%{"dpop_jkt" => "not-a-thumbprint"}, "invalid_request"},
            {%{"scope" => "notes:read admin"}, "invalid_scope"},
            {%{"resource" => "https://elsewhere.test/mcp"}, "invalid_target"},
            {%{"resource" => "https://mcp.test/mcp?x=1"}, "invalid_target"},
            {%{"response_type" => "token"}, "unsupported_response_type"}
          ] do
        {params, _} = authorize_params(client, extra)
        params = Map.reject(params, &is_nil(elem(&1, 1)))
        conn = get_path("/oauth/authorize?" <> URI.encode_query(params))
        assert conn.status == 302, "#{inspect(extra)}"
        [location] = Plug.Conn.get_resp_header(conn, "location")
        query = URI.decode_query(URI.parse(location).query)
        assert query["error"] == error, "#{inspect(extra)}: #{inspect(query)}"
        assert query["iss"] == TestAuth.issuer()
        assert query["state"] == "xyz"
        refute Map.has_key?(query, "code")
      end
    end

    @tag config: [
           resources: [
             [id: "https://mcp.test/mcp", scopes: ["a"], client_auth_methods: ["private_key_jwt"]]
           ]
         ]
    test "a public client at a resource that only takes clients with keys" do
      client = TestClient.new(public: true)
      {params, _} = authorize_params(client)
      assert {:redirect, url} = Gatekeep.Authorization.check(TestAuth.config(), params)
      assert URI.decode_query(URI.parse(url).query)["error"] == "unauthorized_client"
    end
  end

  describe "dynamic client registration" do
    test "registers a public client that signs in like any other" do
      conn =
        post_json("/oauth/register", %{
          "redirect_uris" => ["http://127.0.0.1/cb"],
          "client_name" => "Inspector"
        })

      assert conn.status == 201
      body = json_body(conn)
      assert "gkc_" <> _ = body["client_id"]
      assert body["token_endpoint_auth_method"] == "none"

      {verifier, challenge} = TestClient.pkce()

      conn =
        get_path(
          "/oauth/authorize?" <>
            URI.encode_query(%{
              "client_id" => body["client_id"],
              "redirect_uri" => "http://127.0.0.1:4444/cb",
              "response_type" => "code",
              "code_challenge" => challenge,
              "code_challenge_method" => "S256"
            })
        )

      assert conn.resp_body == "consent for Inspector"
      assert_received {:consent, request}
      {:ok, url} = Gatekeep.Authorization.approve(TestAuth.config(), request, subject: "u")
      code = URI.decode_query(URI.parse(url).query)["code"]

      conn =
        post_form("/oauth/token", %{
          "grant_type" => "authorization_code",
          "client_id" => body["client_id"],
          "code" => code,
          "code_verifier" => verifier,
          "redirect_uri" => "http://127.0.0.1:4444/cb"
        })

      assert %{"access_token" => _, "refresh_token" => _} = json_body(conn)
    end

    test "refuses redirect URIs a browser could be tricked by, and confidential clients" do
      for uris <- [
            ["javascript:alert(1)"],
            ["data:text/html,hi"],
            ["http://evil.example/cb"],
            ["https://x.example/cb#frag"],
            ["https://user:pw@x.example/cb"],
            [],
            "https://x.example/cb"
          ] do
        conn = post_json("/oauth/register", %{"redirect_uris" => uris})
        assert conn.status == 400, inspect(uris)
        assert json_body(conn)["error"] == "invalid_redirect_uri"
      end

      conn =
        post_json("/oauth/register", %{
          "redirect_uris" => ["https://x.example/cb"],
          "token_endpoint_auth_method" => "client_secret_basic"
        })

      assert json_body(conn)["error"] == "invalid_client_metadata"
    end
  end

  describe "endpoint routing and configuration" do
    @tag config: [registered_client_prefix: "rvc_"]
    test "registered client IDs use the configured prefix, and only it resolves" do
      conn = post_json("/oauth/register", %{"redirect_uris" => ["http://127.0.0.1/cb"]})
      assert "rvc_" <> _ = client_id = json_body(conn)["client_id"]
      config = TestAuth.config()
      assert {:ok, %{kind: :registered}} = Gatekeep.Clients.fetch(config, client_id)
      assert {:error, _} = Gatekeep.Clients.fetch(config, "gkc_" <> binary_part(client_id, 4, 24))

      for bad <- ["", "rvc", "https://", "a-b_"] do
        assert_raise ArgumentError, fn ->
          Gatekeep.Config.new!(TestAuth.base_config(name: TestAuth, registered_client_prefix: bad))
        end
      end
    end

    @tag config: [issuer: "https://auth.test/tenant"]
    test "an issuer with a path serves its endpoints under that path" do
      as = json_body(get_path("/.well-known/oauth-authorization-server/tenant"))
      assert as["token_endpoint"] == "https://auth.test/tenant/oauth/token"

      conn = post_form("/tenant/oauth/token", %{"grant_type" => "authorization_code"})
      assert {conn.status, json_body(conn)["error"]} == {401, "invalid_client"}
      assert post_form("/oauth/token", %{"grant_type" => "authorization_code"}).status == 404
    end

    test "an oversized registration body is refused, not a crash" do
      conn = post_json("/oauth/register", %{"client_name" => String.duplicate("x", 70_000)})
      assert {conn.status, json_body(conn)["error"]} == {413, "invalid_client_metadata"}
    end

    test "default scopes must be scopes the resource offers" do
      assert_raise ArgumentError, ~r/default scopes it does not offer/, fn ->
        Gatekeep.Config.new!(
          TestAuth.base_config(
            name: TestAuth,
            resources: [[id: TestAuth.mcp(), scopes: ["notes:read"], default_scopes: ["admin"]]]
          )
        )
      end
    end
  end

  def post_json(path, body) do
    Plug.Test.conn(:post, path, JSON.encode!(body))
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> call()
  end
end
