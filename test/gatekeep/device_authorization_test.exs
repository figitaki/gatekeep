defmodule Gatekeep.DeviceAuthorizationTest do
  use Gatekeep.Case

  import Ecto.Query, only: [from: 2]

  alias Gatekeep.DeviceAuthorization
  alias Gatekeep.Storage.Ecto.DeviceCode

  @grant "urn:ietf:params:oauth:grant-type:device_code"
  @cli_api "https://api.test/cli"

  setup do
    TestAuth.put_config(
      device_verification_uri: "/device",
      clients: [
        [client_id: "cli", public: true, grant_types: [@grant, "refresh_token"]],
        [client_id: "other-cli", public: true, grant_types: [@grant]],
        [client_id: "web", public: true, redirect_uris: ["https://web.example/cb"]]
      ],
      resources:
        TestAuth.base_config()[:resources] ++
          [
            [
              id: @cli_api,
              scopes: [{"cli", "Act as you"}],
              client_auth_methods: ["none"],
              allowed_clients: ["cli"]
            ]
          ]
    )

    :ok
  end

  defp start(client_id \\ "cli", extra \\ %{}) do
    post_form(
      "/oauth/device_authorization",
      Map.merge(%{"client_id" => client_id, "resource" => TestAuth.mcp()}, extra)
    )
  end

  defp poll(device_code, client_id \\ "cli") do
    post_form("/oauth/token", %{
      "grant_type" => @grant,
      "client_id" => client_id,
      "device_code" => device_code
    })
  end

  defp error(conn), do: {conn.status, json_body(conn)["error"]}

  # As if the last poll were `seconds` ago.
  defp wait(seconds) do
    Gatekeep.TestRepo.update_all(DeviceCode,
      set: [last_polled_at: DateTime.add(DateTime.utc_now(), -seconds)]
    )
  end

  defp interval do
    [interval] = Gatekeep.TestRepo.all(from d in DeviceCode, select: d.interval)
    interval
  end

  test "a device signs in: pending, approved on another device, tokens that refresh" do
    conn = start("cli", %{"scope" => "notes:read"})
    assert conn.status == 200
    assert Plug.Conn.get_resp_header(conn, "cache-control") == ["no-store"]

    %{"device_code" => device_code, "user_code" => user_code} = body = json_body(conn)
    assert user_code =~ ~r/\A[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}\z/
    assert body["verification_uri"] == "https://auth.test/device"
    assert body["verification_uri_complete"] == "https://auth.test/device?user_code=#{user_code}"
    assert body["expires_in"] == 600
    assert body["interval"] == 5

    assert error(poll(device_code)) == {400, "authorization_pending"}

    # People type codes any way: lowercase, without the dash.
    typed = user_code |> String.downcase() |> String.replace("-", " ")
    assert {:ok, request} = DeviceAuthorization.lookup(TestAuth.config(), typed)
    assert request.user_code == user_code
    assert request.client.client_id == "cli"
    assert request.resource.id == TestAuth.mcp()
    assert request.scope_descriptions == %{"notes:read" => "Read notes"}

    assert :ok =
             DeviceAuthorization.approve(TestAuth.config(), typed,
               subject: "user:7",
               owner: "account:7"
             )

    wait(5)
    conn = poll(device_code)
    assert conn.status == 200

    %{"access_token" => access, "refresh_token" => refresh, "token_type" => "Bearer"} =
      json_body(conn)

    assert json_body(conn)["scope"] == "notes:read"
    assert get_path("/mcp", bearer(access)).resp_body == "hello user:7"
    assert [%{grant_type: @grant, owner: "account:7"}] = TestAuth.list_grants(subject: "user:7")

    conn =
      post_form("/oauth/token", %{
        "grant_type" => "refresh_token",
        "client_id" => "cli",
        "refresh_token" => refresh
      })

    assert conn.status == 200
    assert json_body(conn)["refresh_token"] != refresh
  end

  test "polling faster than the interval gets slow_down, and the interval grows each time" do
    %{"device_code" => device_code} = json_body(start())

    assert error(poll(device_code)) == {400, "authorization_pending"}
    assert error(poll(device_code)) == {400, "slow_down"}
    assert interval() == 10

    wait(9)
    assert error(poll(device_code)) == {400, "slow_down"}
    assert interval() == 15

    wait(15)
    assert error(poll(device_code)) == {400, "authorization_pending"}
    assert interval() == 15
  end

  test "an expired code is expired_token, and can't be looked up or approved" do
    %{"device_code" => device_code, "user_code" => user_code} = json_body(start())
    Gatekeep.TestRepo.update_all(DeviceCode, set: [expires_at: ~U[2020-01-01 00:00:00Z]])

    assert error(poll(device_code)) == {400, "expired_token"}
    assert DeviceAuthorization.lookup(TestAuth.config(), user_code) == {:error, :expired_user_code}

    assert DeviceAuthorization.approve(TestAuth.config(), user_code, subject: "user:1") ==
             {:error, :expired_user_code}
  end

  test "a denied request is access_denied, and can't be approved afterwards" do
    %{"device_code" => device_code, "user_code" => user_code} = json_body(start())
    assert :ok = DeviceAuthorization.deny(TestAuth.config(), user_code)

    assert error(poll(device_code)) == {400, "access_denied"}

    assert DeviceAuthorization.approve(TestAuth.config(), user_code, subject: "user:1") ==
             {:error, :invalid_user_code}
  end

  test "a redeemed code is redeemed once; presenting it again revokes the grant" do
    %{"device_code" => device_code, "user_code" => user_code} = json_body(start())
    :ok = DeviceAuthorization.approve(TestAuth.config(), user_code, subject: "user:1")
    %{"access_token" => access} = json_body(poll(device_code))

    assert DeviceAuthorization.lookup(TestAuth.config(), user_code) ==
             {:error, :invalid_user_code}

    wait(60)
    assert error(poll(device_code)) == {400, "invalid_grant"}
    assert get_path("/mcp", bearer(access)).status == 401
  end

  test "another client's device code is invalid_grant and changes nothing" do
    %{"device_code" => device_code} = json_body(start())

    assert error(poll(device_code, "other-cli")) == {400, "invalid_grant"}
    assert error(poll(device_code)) == {400, "authorization_pending"}
    assert error(poll("gkd_unknown")) == {400, "invalid_grant"}
  end

  test "approval may narrow the scopes, never widen or empty them" do
    %{"device_code" => device_code, "user_code" => user_code} =
      json_body(start("cli", %{"scope" => "notes:read notes:write"}))

    config = TestAuth.config()

    assert DeviceAuthorization.approve(config, user_code, subject: "u", scopes: ["other:read"]) ==
             {:error, :invalid_scopes}

    assert DeviceAuthorization.approve(config, user_code, subject: "u", scopes: []) ==
             {:error, :invalid_scopes}

    assert :ok =
             DeviceAuthorization.approve(config, user_code, subject: "u", scopes: ["notes:write"])

    assert json_body(poll(device_code))["scope"] == "notes:write"
  end

  test "a client that doesn't list the grant can't start it, or poll" do
    assert error(start("web")) == {400, "unauthorized_client"}
    assert error(poll("gkd_x", "web")) == {400, "unauthorized_client"}
    assert error(start("nobody")) == {401, "invalid_client"}
  end

  test "a request for an unknown resource or scope is refused" do
    assert error(start("cli", %{"resource" => "https://nope.test"})) == {400, "invalid_target"}
    assert error(start("cli", %{"scope" => "notes:admin"})) == {400, "invalid_scope"}
  end

  describe "a resource that lists its allowed clients" do
    test "issues device tokens to those clients only" do
      assert error(start("other-cli", %{"resource" => @cli_api})) == {400, "unauthorized_client"}

      %{"device_code" => device_code, "user_code" => user_code} =
        json_body(start("cli", %{"resource" => @cli_api}))

      :ok = DeviceAuthorization.approve(TestAuth.config(), user_code, subject: "user:1")
      %{"access_token" => access} = json_body(poll(device_code))

      assert {:ok, %{subject: "user:1"}} =
               Gatekeep.Token.authenticate(TestAuth.config(), @cli_api, %{
                 authorization: "Bearer " <> access
               })
    end

    test "refuses authorization requests from other clients" do
      client = TestClient.new()
      {params, _} = authorize_params(client, %{"resource" => @cli_api, "scope" => "cli"})
      conn = get_path("/oauth/authorize?" <> URI.encode_query(params))
      assert conn.status == 302
      assert Plug.Conn.get_resp_header(conn, "location") |> hd() =~ "error=unauthorized_client"
    end

    test "doesn't turn on dynamic client registration by itself" do
      config =
        Gatekeep.Config.new!(
          TestAuth.base_config(
            name: TestAuth,
            resources: [[id: @cli_api, client_auth_methods: ["none"], allowed_clients: ["cli"]]]
          )
          |> Keyword.delete(:default_resource)
        )

      refute Gatekeep.Config.public_clients?(config)
      refute Map.has_key?(Gatekeep.Metadata.authorization_server(config), "registration_endpoint")
    end
  end

  test "the metadata advertises the endpoint and the grant" do
    as = json_body(get_path("/.well-known/oauth-authorization-server"))
    assert as["device_authorization_endpoint"] == "https://auth.test/oauth/device_authorization"
    assert @grant in as["grant_types_supported"]
  end

  test "without a verification URI the grant is off" do
    TestAuth.put_config(clients: [[client_id: "cli", public: true, grant_types: [@grant]]])

    assert start().status == 404
    assert error(poll("gkd_x")) == {400, "unsupported_grant_type"}
    as = json_body(get_path("/.well-known/oauth-authorization-server"))
    refute Map.has_key?(as, "device_authorization_endpoint")
    refute @grant in as["grant_types_supported"]
  end
end
