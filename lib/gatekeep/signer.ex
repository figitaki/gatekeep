defmodule Gatekeep.Signer do
  @moduledoc """
  Signs the JWTs Gatekeep mints: JWT access tokens (RFC 9068), when
  `access_token_format: :jwt`.

  A signer turns a header and claims into a compact JWS, so the private key
  can live anywhere that can produce a signature: in memory
  (`Gatekeep.Signer.Local`), in a KMS or HSM, or in an external signer such
  as a wallet service. Gatekeep never needs the private key itself.

  Configure it as `signer: {MySigner, opts}`. `opts` is passed to every call.
  """

  @doc """
  Signs `claims` with `header` and returns a compact JWS. The signer sets
  `alg` and `kid` in the header. Return `{:error, reason}` when no key is
  available.
  """
  @callback sign(header :: map(), claims :: map(), opts :: keyword()) ::
              {:ok, String.t()} | {:error, term()}

  @doc """
  The public keys that verify the signer's JWTs, as JWK maps with `kid`,
  served at the JWKS endpoint. Include retiring keys until their tokens
  expire.
  """
  @callback public_keys(opts :: keyword()) :: [map()]

  @doc false
  def sign(%Gatekeep.Config{signer: {module, opts}}, header, claims),
    do: module.sign(header, claims, opts)

  def sign(%Gatekeep.Config{signer: nil}, _header, _claims), do: {:error, :no_signer}

  @doc false
  def public_keys(%Gatekeep.Config{signer: {module, opts}}), do: module.public_keys(opts)
  def public_keys(%Gatekeep.Config{signer: nil}), do: []
end

defmodule Gatekeep.Signer.Local do
  @moduledoc """
  A `Gatekeep.Signer` with an ES256 key in configuration, for development
  and for deployments that keep the key in their own secrets.

      signer: {Gatekeep.Signer.Local, key: System.fetch_env!("GATEKEEP_SIGNING_KEY"), kid: "2026-11"}

  `:key` is a private P-256 JWK as a JSON string or map (with `d`).
  `generate/0` makes one.
  """

  @behaviour Gatekeep.Signer

  alias Gatekeep.JOSE

  @doc "Generates a private P-256 JWK map."
  @spec generate() :: map()
  def generate do
    {<<4, x::binary-size(32), y::binary-size(32)>>, d} = :crypto.generate_key(:ecdh, :secp256r1)

    %{
      "kty" => "EC",
      "crv" => "P-256",
      "x" => JOSE.b64url_encode(x),
      "y" => JOSE.b64url_encode(y),
      "d" => JOSE.b64url_encode(d)
    }
  end

  @impl true
  def sign(header, claims, opts) do
    with {:ok, jwk} <- private_jwk(opts),
         {:ok, d} <- JOSE.b64url_decode(jwk["d"]) do
      header = Map.put(header, "kid", kid(opts, jwk))
      {:ok, JOSE.sign(header, claims, %{alg: "ES256", private: d})}
    else
      _ -> {:error, :no_signing_key}
    end
  end

  @impl true
  def public_keys(opts) do
    case private_jwk(opts) do
      {:ok, jwk} ->
        [
          jwk
          |> Map.take(["kty", "crv", "x", "y"])
          |> Map.merge(%{"kid" => kid(opts, jwk), "alg" => "ES256", "use" => "sig"})
        ]

      :error ->
        []
    end
  end

  defp private_jwk(opts) do
    case opts[:key] do
      %{"kty" => "EC", "crv" => "P-256", "d" => _} = jwk -> {:ok, jwk}
      json when is_binary(json) -> json |> JSON.decode() |> then(&private_jwk(key: elem(&1, 1)))
      _ -> :error
    end
  rescue
    _ -> :error
  end

  defp kid(opts, jwk) do
    opts[:kid] || jwk |> Map.take(["kty", "crv", "x", "y"]) |> JOSE.thumbprint() |> elem(1)
  end
end
