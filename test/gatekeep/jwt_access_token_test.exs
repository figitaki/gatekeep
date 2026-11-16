defmodule Gatekeep.JWTAccessTokenTest do
  use Gatekeep.Case

  setup do
    key = Gatekeep.Signer.Local.generate()

    TestAuth.put_config(
      access_token_format: :jwt,
      signer: {Gatekeep.Signer.Local, key: key, kid: "k1"}
    )

    %{client: TestClient.new()}
  end

  test "access tokens are RFC 9068 JWTs that verify with the JWKS endpoint", %{client: client} do
    %{"access_token" => access} = sign_in(client)
    {:ok, jws} = Gatekeep.JOSE.decode(access)
    assert jws.header["typ"] == "at+jwt"
    assert jws.header["kid"] == "k1"

    assert %{"iss" => "https://auth.test", "aud" => "https://mcp.test/mcp", "sub" => "user:1"} =
             jws.claims

    as = json_body(get_path("/.well-known/oauth-authorization-server"))
    assert as["jwks_uri"] == "https://auth.test/oauth/jwks"
    %{"keys" => [jwk]} = json_body(get_path("/oauth/jwks"))
    refute Map.has_key?(jwk, "d")
    assert Gatekeep.JOSE.verify(jws, jwk, ["ES256"])
  end

  test "revoked JWT access tokens are refused like opaque ones", %{client: client} do
    %{"access_token" => access, "refresh_token" => refresh} = sign_in(client)
    assert get_path("/mcp", bearer(access)).status == 200
    post_form("/oauth/revoke", Map.put(TestClient.client_auth(client), "token", refresh))
    assert get_path("/mcp", bearer(access)).status == 401
  end

  test "a JWT access token needs a signer" do
    assert_raise ArgumentError, ~r/needs a :signer/, fn ->
      Gatekeep.Config.new!(
        Keyword.merge(TestAuth.base_config(), name: TestAuth, access_token_format: :jwt)
      )
    end
  end
end
