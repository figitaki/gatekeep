defmodule Gatekeep.ClientAuth do
  @moduledoc """
  Client authentication at the token and revocation endpoints:

    * `private_key_jwt` (RFC 7523 §2.2) - a client assertion signed with a key
      from the client's key set. `aud` must be the issuer; clients listed in
      `:token_endpoint_audience_clients` may also name the token endpoint.
      Each assertion's `jti` is accepted once.
    * `client_secret_basic` and `client_secret_post` - for pre-registered
      clients with `:client_secret_sha256`. The secret is compared in constant
      time with its stored hash.
    * `none` - a public client named by `client_id`, which relies on PKCE.

  Every failure returns `{:error, reason}` with a specific atom so tests and
  logs can tell cases apart; the endpoints answer `invalid_client` for all of
  them.
  """

  alias Gatekeep.{Client, Clients, Config, JOSE, Storage, Util}

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  @max_assertion_lifetime 5 * 60

  @doc """
  Authenticates the client of a token or revocation request. `authorization`
  is the request's `Authorization` header, or nil.
  """
  @spec authenticate(Config.t(), map(), String.t() | nil, keyword()) ::
          {:ok, Client.t(), String.t()} | {:error, atom()}
  def authenticate(%Config{} = config, params, authorization, opts \\ []) do
    cond do
      Map.has_key?(params, "client_assertion") or Map.has_key?(params, "client_assertion_type") ->
        with {:ok, client} <- verify_client_assertion(config, params, opts),
             do: {:ok, client, "private_key_jwt"}

      basic = basic_credentials(authorization) ->
        with {client_id, secret} <- basic,
             :ok <- Util.expect(params["client_id"] in [nil, client_id], :client_id_mismatch),
             {:ok, client} <- check_secret(config, client_id, secret) do
          {:ok, client, "client_secret_basic"}
        else
          :malformed -> {:error, :malformed_basic_credentials}
          {:error, _} = error -> error
        end

      Map.has_key?(params, "client_secret") ->
        with {:ok, client} <- check_secret(config, params["client_id"], params["client_secret"]),
             do: {:ok, client, "client_secret_post"}

      is_binary(params["client_id"]) ->
        with {:ok, client} <- Clients.fetch(config, params["client_id"]),
             :ok <- Util.expect("none" in client.auth_methods, :auth_method_not_allowed),
             do: {:ok, client, "none"}

      true ->
        {:error, :no_client_authentication}
    end
  end

  # RFC 6749 §2.3.1: both parts are form-urlencoded before base64.
  # HTTP authentication schemes are case-insensitive (RFC 9110 §11.1).
  defp basic_credentials(header) when is_binary(header) do
    case String.split(header, " ", parts: 2) do
      [scheme, encoded] -> if String.downcase(scheme) == "basic", do: decode_basic(encoded)
      _ -> nil
    end
  end

  defp basic_credentials(_), do: nil

  defp decode_basic(encoded) do
    with {:ok, decoded} <- Base.decode64(String.trim(encoded)),
         [id, secret] <- String.split(decoded, ":", parts: 2) do
      {URI.decode_www_form(id), URI.decode_www_form(secret)}
    else
      _ -> :malformed
    end
  rescue
    _ -> :malformed
  end

  defp check_secret(config, client_id, secret) when is_binary(client_id) and is_binary(secret) do
    with {:ok, %Client{secret_hash: hash} = client} when is_binary(hash) <-
           Clients.fetch(config, client_id),
         true <- Plug.Crypto.secure_compare(Gatekeep.hash_client_secret(secret), hash) do
      {:ok, client}
    else
      {:error, _} = error -> error
      _ -> {:error, :bad_secret}
    end
  end

  defp check_secret(_config, _client_id, _secret), do: {:error, :bad_secret}

  @doc """
  Verifies a `private_key_jwt` client assertion and returns its client.
  `opts[:now]` overrides the current Unix time, for tests.
  """
  @spec verify_client_assertion(Config.t(), map(), keyword()) ::
          {:ok, Client.t()} | {:error, atom()}
  def verify_client_assertion(%Config{} = config, params, opts \\ []) do
    now = Keyword.get_lazy(opts, :now, &Util.now/0)
    skew = config.clock_skew

    with @assertion_type <- params["client_assertion_type"],
         assertion when is_binary(assertion) <- params["client_assertion"],
         {:ok, jws} <- JOSE.decode(assertion),
         %{"iss" => iss, "sub" => iss, "aud" => aud, "exp" => exp, "iat" => iat, "jti" => jti}
         when is_binary(iss) and is_integer(exp) and is_integer(iat) and is_binary(jti) <-
           jws.claims,
         :ok <- Util.expect(params["client_id"] in [nil, iss], :client_id_mismatch),
         :ok <- Util.expect(audience?(config, aud, iss), :wrong_audience),
         {:ok, client} <- Clients.fetch(config, iss),
         :ok <- Util.expect("private_key_jwt" in client.auth_methods, :auth_method_not_allowed),
         :ok <- verify_signature(config, jws, client),
         :ok <- Util.expect(exp > now - skew, :expired),
         :ok <- Util.expect(iat <= now + skew, :issued_in_future),
         :ok <- check_nbf(jws.claims["nbf"], now, skew),
         :ok <- Util.expect(exp - iat <= @max_assertion_lifetime, :assertion_too_long),
         :ok <- Util.expect(jti != "" and byte_size(jti) <= 255, :bad_jti),
         :ok <-
           Storage.call(config, :remember_jti, [
             "client_assertion",
             iss,
             jti,
             DateTime.from_unix!(exp + skew)
           ]) do
      {:ok, client}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_assertion}
    end
  end

  # RFC 7519 §4.1.5: nbf is optional, but honored when present.
  defp check_nbf(nil, _now, _skew), do: :ok

  defp check_nbf(nbf, now, skew) when is_integer(nbf),
    do: Util.expect(nbf <= now + skew, :not_yet_valid)

  defp check_nbf(_nbf, _now, _skew), do: {:error, :invalid_assertion}

  defp audience?(config, aud, iss) when is_binary(aud) do
    aud == config.issuer or
      (aud == Config.endpoint(config, :token) and iss in config.token_endpoint_audience_clients)
  end

  defp audience?(_config, _aud, _iss), do: false

  defp verify_signature(config, jws, client) do
    keys =
      case jws.header["kid"] do
        kid when is_binary(kid) ->
          case Clients.key(config, client, kid) do
            {:ok, key} -> [key]
            _ -> []
          end

        _ ->
          client.keys
      end

    if Enum.any?(keys, &JOSE.verify(jws, &1, config.client_assertion_algs)),
      do: :ok,
      else: {:error, :bad_signature}
  end
end
