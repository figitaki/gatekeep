defmodule Gatekeep.DPoP do
  @moduledoc """
  DPoP proof verification (RFC 9449 §4.3).

  A proof is checked for its `typ`, an allowed `alg`, a signature by the
  public key in its `jwk` header, `htm` and `htu` matching the request,
  `iat` within `:dpop_proof_window` plus `:clock_skew`, `ath` covering the
  access token at a protected resource, and a `jti` not seen before. Gatekeep
  issues no DPoP nonces; `iat` and the replay cache bound how long a proof
  works.

  Every failure returns `{:error, reason}` with a specific atom so tests and
  logs can tell cases apart. The HTTP layer maps them all to
  `invalid_dpop_proof`.
  """

  alias Gatekeep.{Config, JOSE, Storage, Util}

  @type request :: %{
          required(:method) => String.t(),
          required(:url) => String.t(),
          optional(:access_token) => String.t() | nil
        }

  @doc """
  Verifies the DPoP proof of a request and returns the thumbprint (`jkt`) of
  its key. `proofs` is every `DPoP` header value the request carried.
  `request.url` is the public URL of the endpoint, built from configuration,
  never from the Host header. `request.access_token` is set at a protected
  resource, where `ath` must match it.

  `opts[:now]` overrides the current Unix time, for tests.
  """
  @spec verify([String.t()], request(), Config.t(), keyword()) ::
          {:ok, String.t()} | {:error, atom()}
  def verify(proofs, request, config, opts \\ [])

  def verify([proof], request, %Config{} = config, opts) do
    now = Keyword.get_lazy(opts, :now, &Util.now/0)
    window = config.dpop_proof_window
    skew = config.clock_skew
    algs = config.dpop_signing_algs

    with {:ok, jws} <- JOSE.decode(proof),
         %{"typ" => "dpop+jwt", "jwk" => jwk} when is_map(jwk) <- jws.header,
         :ok <- Util.expect(jws.header["alg"] in algs, :bad_alg),
         :ok <- Util.expect(JOSE.public_key?(jwk), :bad_dpop_key),
         :ok <- Util.expect(JOSE.verify(jws, jwk, algs), :bad_signature),
         %{"jti" => jti, "htm" => htm, "htu" => htu, "iat" => iat}
         when is_binary(jti) and is_integer(iat) <- jws.claims,
         :ok <- Util.expect(jti != "" and byte_size(jti) <= 255, :bad_jti),
         :ok <- Util.expect(htm == request.method, :wrong_method),
         :ok <- Util.expect(htu_matches?(htu, request.url), :wrong_url),
         :ok <- Util.expect(iat >= now - window - skew, :expired),
         :ok <- Util.expect(iat <= now + skew, :issued_in_future),
         :ok <- check_ath(jws.claims["ath"], request[:access_token]),
         {:ok, jkt} <- JOSE.thumbprint(jwk),
         :ok <- remember(config, jkt, jti, iat + window + skew + 1) do
      {:ok, jkt}
    else
      {:error, :malformed} -> {:error, :invalid_dpop_proof}
      {:error, _} = error -> error
      _ -> {:error, :invalid_dpop_proof}
    end
  end

  def verify([], _request, _config, _opts), do: {:error, :missing_dpop_proof}
  def verify(_proofs, _request, _config, _opts), do: {:error, :multiple_dpop_proofs}

  # The replay cache is scoped to the proof key: a jti is unique per key.
  # The proof is accepted through the second iat + window + skew, so its
  # entry is kept until the second after that.
  defp remember(config, jkt, jti, expires_at) do
    case Storage.call(config, :remember_jti, ["dpop", jkt, jti, DateTime.from_unix!(expires_at)]) do
      :ok -> :ok
      {:error, :replayed} -> {:error, :replayed}
    end
  end

  # At a protected resource, ath must match the access token (RFC 9449 §4.3
  # step 12). The token endpoint has no token to cover.
  defp check_ath(_ath, nil), do: :ok

  defp check_ath(ath, token) when is_binary(ath),
    do: Util.expect(ath == JOSE.digest(token), :ath_mismatch)

  defp check_ath(_ath, _token), do: {:error, :missing_ath}

  # RFC 9449 §4.3: compare without query and fragment, after normalizing the
  # scheme and host case and the default port.
  defp htu_matches?(htu, url) when is_binary(htu) do
    case normalize(htu) do
      :invalid -> false
      normalized -> normalized == normalize(url)
    end
  end

  defp htu_matches?(_htu, _url), do: false

  defp normalize(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host} = uri when is_binary(scheme) and is_binary(host) ->
        scheme = String.downcase(scheme)
        port = if uri.port in [nil, URI.default_port(scheme)], do: "", else: ":#{uri.port}"
        "#{scheme}://#{String.downcase(host)}#{port}#{uri.path || "/"}"

      _ ->
        :invalid
    end
  end
end
