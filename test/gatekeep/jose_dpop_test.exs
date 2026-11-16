defmodule Gatekeep.JOSEDPoPTest do
  use Gatekeep.Case

  import Ecto.Query, only: [from: 2]

  alias Gatekeep.{DPoP, JOSE}

  @vectors "test/support/fixtures/rfc9449_vectors.json" |> File.read!() |> JSON.decode!()

  describe "JOSE" do
    test "verifies the RFC 7515 A.3 ES256 example and rejects a changed payload or other alg" do
      jwk = %{
        "kty" => "EC",
        "crv" => "P-256",
        "x" => "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y" => "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
      }

      jws =
        "eyJhbGciOiJFUzI1NiJ9." <>
          "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." <>
          "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

      assert {:ok, decoded} = JOSE.decode(jws)
      assert JOSE.verify(decoded, jwk, ["ES256"])
      refute JOSE.verify(decoded, jwk, ["RS256"])
      refute JOSE.verify(%{decoded | signing_input: decoded.signing_input <> "x"}, jwk, ["ES256"])

      # The key's own alg, use, and key_ops restrict it.
      assert JOSE.verify(decoded, Map.merge(jwk, %{"alg" => "ES256", "use" => "sig"}), ["ES256"])
      assert JOSE.verify(decoded, Map.put(jwk, "key_ops", ["verify"]), ["ES256"])
      refute JOSE.verify(decoded, Map.put(jwk, "alg", "ES384"), ["ES256"])
      refute JOSE.verify(decoded, Map.put(jwk, "use", "enc"), ["ES256"])
      refute JOSE.verify(decoded, Map.put(jwk, "key_ops", ["encrypt"]), ["ES256"])
    end

    test "refuses a header with critical extensions" do
      key = TestClient.ec_key("k")
      assert {:ok, _} = JOSE.decode(JOSE.sign(%{}, %{"a" => 1}, key))
      assert JOSE.decode(JOSE.sign(%{"crit" => ["exp"]}, %{"a" => 1}, key)) == {:error, :malformed}
    end

    test "computes the RFC 7638 example thumbprint" do
      jwk = %{
        "kty" => "RSA",
        "e" => "AQAB",
        "n" =>
          "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
      }

      assert JOSE.thumbprint(jwk) == {:ok, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}

      # Any private member makes it a private key, not only d.
      assert JOSE.public_key?(jwk)
      for member <- ~w(d p q dp dq qi oth), do: refute(JOSE.public_key?(Map.put(jwk, member, "x")))
    end

    test "never accepts none or HMAC, whatever the caller allows" do
      key = TestClient.ec_key("k")
      [h, c, _] = key |> then(&JOSE.sign(%{}, %{"a" => 1}, &1)) |> String.split(".")
      none_header = JOSE.b64url_encode(~s({"alg":"none"}))
      {:ok, decoded} = JOSE.decode(none_header <> "." <> c <> ".")
      refute JOSE.verify(decoded, key.public, ["none", "ES256"])
      {:ok, hs} = JOSE.decode(JOSE.b64url_encode(~s({"alg":"HS256"})) <> "." <> c <> "." <> h)
      refute JOSE.verify(hs, %{"kty" => "oct", "k" => "c2VjcmV0"}, ["HS256"])
    end
  end

  describe "DPoP proofs" do
    setup do
      %{config: TestAuth.config(), key: TestClient.ec_key(nil)}
    end

    @url "https://auth.test/oauth/token"

    test "accepts the RFC 9449 example proofs, with the RFC's thumbprint", %{config: config} do
      %{"jkt" => jkt, "token_request" => t, "resource_request" => r} = @vectors

      assert DPoP.verify([t["proof"]], %{method: t["method"], url: t["url"]}, config, now: t["now"]) ==
               {:ok, jkt}

      # Their jti expire in 2019, so the replay cache may prune them at once;
      # replay is covered with fresh proofs below.
      request = %{method: r["method"], url: r["url"], access_token: r["access_token"]}
      assert DPoP.verify([r["proof"]], request, config, now: r["now"]) == {:ok, jkt}
    end

    test "refuses a replayed proof", %{config: config, key: key} do
      proof = TestClient.dpop_proof(key, "POST", @url)
      assert {:ok, _} = DPoP.verify([proof], %{method: "POST", url: @url}, config)
      assert DPoP.verify([proof], %{method: "POST", url: @url}, config) == {:error, :replayed}
    end

    test "matches htm and htu, ignoring query and default port", %{config: config, key: key} do
      request = %{method: "POST", url: @url}

      assert {:ok, _} =
               DPoP.verify(
                 [TestClient.dpop_proof(key, "POST", "HTTPS://Auth.test:443/oauth/token?x=1")],
                 request,
                 config
               )

      assert DPoP.verify([TestClient.dpop_proof(key, "GET", @url)], request, config) ==
               {:error, :wrong_method}

      assert DPoP.verify(
               [TestClient.dpop_proof(key, "POST", "https://auth.test/oauth/revoke")],
               request,
               config
             ) ==
               {:error, :wrong_url}

      assert DPoP.verify(
               [TestClient.dpop_proof(key, "POST", "https://evil.test/oauth/token")],
               request,
               config
             ) ==
               {:error, :wrong_url}
    end

    test "accepts iat within 60 seconds plus 30 of skew, and nothing outside", %{
      config: config,
      key: key
    } do
      now = TestClient.now()
      request = %{method: "POST", url: @url}
      proof = &TestClient.dpop_proof(key, "POST", @url, iat: now + &1)

      oldest = proof.(-90)
      assert {:ok, _} = DPoP.verify([oldest], request, config, now: now)

      # Its replay entry outlives the last second it is accepted in.
      [%{expires_at: expires_at}] =
        Gatekeep.TestRepo.all(
          from j in "gatekeep_seen_jtis",
            where: j.kind == "dpop",
            select: %{expires_at: j.expires_at}
        )

      assert expires_at |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix() > now
      assert DPoP.verify([proof.(-91)], request, config, now: now) == {:error, :expired}
      assert {:ok, _} = DPoP.verify([proof.(30)], request, config, now: now)
      assert DPoP.verify([proof.(31)], request, config, now: now) == {:error, :issued_in_future}
    end

    test "covers the access token with ath at a protected resource", %{config: config, key: key} do
      url = "https://mcp.test/mcp"
      request = %{method: "GET", url: url, access_token: "token-a"}

      assert {:ok, _} =
               DPoP.verify(
                 [TestClient.dpop_proof(key, "GET", url, access_token: "token-a")],
                 request,
                 config
               )

      assert DPoP.verify(
               [TestClient.dpop_proof(key, "GET", url, access_token: "token-b")],
               request,
               config
             ) ==
               {:error, :ath_mismatch}

      assert DPoP.verify([TestClient.dpop_proof(key, "GET", url)], request, config) ==
               {:error, :missing_ath}
    end

    test "refuses proofs that aren't one well-formed DPoP JWT from the key in jwk", %{
      config: config,
      key: key
    } do
      request = %{method: "POST", url: @url}
      good = TestClient.dpop_proof(key, "POST", @url)

      assert DPoP.verify([], request, config) == {:error, :missing_dpop_proof}
      assert DPoP.verify([good, good], request, config) == {:error, :multiple_dpop_proofs}

      assert {:error, _} =
               DPoP.verify([TestClient.dpop_proof(key, "POST", @url, typ: "JWT")], request, config)

      # Signed by another key than the one in its header.
      other = TestClient.ec_key(nil)
      [_h, c, _s] = String.split(good, ".")
      [h2, _c2, _] = TestClient.dpop_proof(other, "POST", @url) |> String.split(".")
      forged = JOSE.sign(%{}, JSON.decode!(Base.url_decode64!(c, padding: false)), key)
      [_, _, s3] = String.split(forged, ".")
      assert DPoP.verify([h2 <> "." <> c <> "." <> s3], request, config) == {:error, :bad_signature}

      # A private key in the header.
      leaky = %{key | public: Map.put(key.public, "d", "x")}

      assert DPoP.verify([TestClient.dpop_proof(leaky, "POST", @url)], request, config) ==
               {:error, :bad_dpop_key}
    end
  end
end
