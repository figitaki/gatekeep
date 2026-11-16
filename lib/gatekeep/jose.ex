defmodule Gatekeep.JOSE do
  @moduledoc """
  The small part of JOSE Gatekeep needs: compact JWS decoding, ES256, PS384,
  and RS256 signatures, and RFC 7638 thumbprints.

  Callers choose which algorithms a JWT type allows; `none` and symmetric
  algorithms are never accepted. Callers also choose the key: keys embedded
  in a JWT header (`jku`, `x5u`, `jwk`) are never used, except the `jwk` of a
  DPoP proof, which is how DPoP works (RFC 9449 §4.2).
  """

  @type decoded :: %{
          header: map(),
          claims: map(),
          signing_input: binary(),
          signature: binary()
        }

  @max_jwt_size 16_384

  # RFC 7518 §6.3.2: every member of an RSA private key.
  @rsa_private ~w(d p q dp dq qi oth)

  @doc """
  Splits and decodes a compact JWS. Does not check the signature. A header
  with `crit` is refused: Gatekeep implements no critical extensions
  (RFC 7515 §4.1.11).
  """
  @spec decode(term()) :: {:ok, decoded()} | {:error, :malformed}
  def decode(jwt) when is_binary(jwt) and byte_size(jwt) <= @max_jwt_size do
    with [h64, c64, s64] <- String.split(jwt, "."),
         {:ok, header_json} <- b64url_decode(h64),
         {:ok, claims_json} <- b64url_decode(c64),
         {:ok, signature} <- b64url_decode(s64),
         {:ok, %{} = header} <- JSON.decode(header_json),
         false <- Map.has_key?(header, "crit"),
         {:ok, %{} = claims} <- JSON.decode(claims_json) do
      {:ok,
       %{header: header, claims: claims, signing_input: h64 <> "." <> c64, signature: signature}}
    else
      _ -> {:error, :malformed}
    end
  end

  def decode(_), do: {:error, :malformed}

  @doc """
  Verifies `decoded` with `jwk`, accepting only the algorithms in `allowed`.
  The key type must match the algorithm, and the key's own `alg`, `use`, and
  `key_ops` must allow verifying with it (RFC 7517 §4).
  """
  @spec verify(decoded(), map(), [String.t()]) :: boolean()
  def verify(%{header: %{"alg" => alg}} = decoded, jwk, allowed) when is_map(jwk) do
    alg in allowed and key_allows?(jwk, alg) and verify_alg(alg, decoded, jwk)
  end

  def verify(_decoded, _jwk, _allowed), do: false

  defp verify_alg("ES256", %{signing_input: input, signature: <<r::256, s::256>>}, jwk) do
    case ec_point(jwk) do
      {:ok, point} ->
        der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
        safe(fn -> :crypto.verify(:ecdsa, :sha256, input, der, [point, :secp256r1]) end)

      :error ->
        false
    end
  end

  defp verify_alg("PS384", %{signing_input: input, signature: signature}, jwk) do
    with {:ok, [e, n]} <- rsa_key(jwk),
         true <- byte_size(signature) == byte_size(n) do
      safe(fn ->
        :crypto.verify(:rsa, :sha384, input, signature, [e, n],
          rsa_padding: :rsa_pkcs1_pss_padding,
          rsa_pss_saltlen: 48,
          rsa_mgf1_md: :sha384
        )
      end)
    else
      _ -> false
    end
  end

  defp verify_alg("RS256", %{signing_input: input, signature: signature}, jwk) do
    with {:ok, [e, n]} <- rsa_key(jwk),
         true <- byte_size(signature) == byte_size(n) do
      safe(fn -> :crypto.verify(:rsa, :sha256, input, signature, [e, n]) end)
    else
      _ -> false
    end
  end

  defp verify_alg(_alg, _decoded, _jwk), do: false

  defp key_allows?(jwk, alg) do
    jwk["alg"] in [nil, alg] and jwk["use"] in [nil, "sig"] and
      case jwk["key_ops"] do
        nil -> true
        ops when is_list(ops) -> "verify" in ops
        _ -> false
      end
  end

  defp safe(fun) do
    fun.() == true
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  @doc """
  True when `jwk` is a public EC P-256 or RSA (2048 to 4096 bits) key with
  no private members.
  """
  @spec public_key?(term()) :: boolean()
  def public_key?(%{"kty" => "EC"} = jwk),
    do: not Map.has_key?(jwk, "d") and ec_point(jwk) != :error

  def public_key?(%{"kty" => "RSA"} = jwk),
    do: not Enum.any?(@rsa_private, &Map.has_key?(jwk, &1)) and rsa_key(jwk) != :error

  def public_key?(_), do: false

  defp ec_point(%{"kty" => "EC", "crv" => "P-256", "x" => x, "y" => y})
       when is_binary(x) and is_binary(y) do
    case {b64url_decode(x), b64url_decode(y)} do
      {{:ok, <<_::binary-size(32)>> = xb}, {:ok, <<_::binary-size(32)>> = yb}} ->
        {:ok, <<4, xb::binary, yb::binary>>}

      _ ->
        :error
    end
  end

  defp ec_point(_), do: :error

  defp rsa_key(%{"kty" => "RSA", "n" => n, "e" => e}) when is_binary(n) and is_binary(e) do
    with {:ok, nb} <- b64url_decode(n),
         {:ok, eb} <- b64url_decode(e),
         bits when bits >= 2048 and bits <= 4096 <- bit_size(strip_zeros(nb)) do
      {:ok, [eb, nb]}
    else
      _ -> :error
    end
  end

  defp rsa_key(_), do: :error

  defp strip_zeros(<<0, rest::binary>>), do: strip_zeros(rest)
  defp strip_zeros(bin), do: bin

  @doc "RFC 7638 JWK thumbprint, SHA-256, base64url without padding."
  @spec thumbprint(map()) :: {:ok, String.t()} | :error
  def thumbprint(%{"kty" => "EC", "crv" => crv, "x" => x, "y" => y})
      when is_binary(crv) and is_binary(x) and is_binary(y) do
    {:ok,
     digest(
       ~s({"crv":#{JSON.encode!(crv)},"kty":"EC","x":#{JSON.encode!(x)},"y":#{JSON.encode!(y)}})
     )}
  end

  def thumbprint(%{"kty" => "RSA", "e" => e, "n" => n}) when is_binary(e) and is_binary(n) do
    {:ok, digest(~s({"e":#{JSON.encode!(e)},"kty":"RSA","n":#{JSON.encode!(n)}}))}
  end

  def thumbprint(_), do: :error

  @doc "base64url SHA-256 of `value`, as in `ath` (RFC 9449) and PKCE S256."
  @spec digest(binary()) :: String.t()
  def digest(value), do: :crypto.hash(:sha256, value) |> b64url_encode()

  @doc false
  def b64url_encode(bin), do: Base.url_encode64(bin, padding: false)

  @doc false
  def b64url_decode(value) when is_binary(value) do
    if String.ends_with?(value, "="), do: :error, else: Base.url_decode64(value, padding: false)
  end

  def b64url_decode(_), do: :error

  @doc """
  Signs `claims` with a private key, returning a compact JWS. `key` is
  `%{alg: "ES256", private: d}` with the raw P-256 scalar, or
  `%{alg: "PS384" | "RS256", private: rsa_private_key}` as
  `:crypto.generate_key/2` returns it. Header fields in `header` are added.
  """
  @spec sign(map(), map(), map()) :: String.t()
  def sign(header, claims, %{alg: alg} = key) do
    input =
      b64url_encode(JSON.encode!(Map.put(header, "alg", alg))) <>
        "." <> b64url_encode(JSON.encode!(claims))

    input <> "." <> b64url_encode(raw_signature(alg, input, key.private))
  end

  defp raw_signature("ES256", input, d) do
    der = :crypto.sign(:ecdsa, :sha256, input, [d, :secp256r1])
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
    <<r::256, s::256>>
  end

  defp raw_signature("PS384", input, private) do
    :crypto.sign(:rsa, :sha384, input, private,
      rsa_padding: :rsa_pkcs1_pss_padding,
      rsa_pss_saltlen: 48,
      rsa_mgf1_md: :sha384
    )
  end

  defp raw_signature("RS256", input, private), do: :crypto.sign(:rsa, :sha256, input, private)
end
