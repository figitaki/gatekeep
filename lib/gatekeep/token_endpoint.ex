defmodule Gatekeep.TokenEndpoint do
  @moduledoc """
  The token endpoint (OAuth 2.1 §3.2) and the revocation endpoint (RFC 7009).

  Grants:

    * `authorization_code`, with PKCE S256. The code is consumed atomically,
      so two concurrent exchanges can't both succeed, and a failed check still
      consumes it: a code gets one attempt. Presenting a consumed code again,
      by the client it was issued to, revokes the grant it created.
    * `refresh_token`. Scopes may narrow, never widen. Resources with
      `rotate_refresh_tokens` (the default) issue a new refresh token each
      time; presenting any replaced one revokes the grant and every token
      issued under it.
    * Extension grants, each a `Gatekeep.Grant` module: the device
      authorization grant (`Gatekeep.DeviceAuthorization`).

  ## DPoP

  A token request may carry a `DPoP` proof (RFC 9449). It is checked before
  the grant, so a bad proof does not use up a code. With a valid proof, the
  access token is bound to the proof's key (`token_type` `DPoP`), and so is
  the refresh token of a new grant. A bound refresh token needs a proof from
  the same key. A code whose authorization request named `dpop_jkt` needs a
  proof from that key. A client whose metadata declares
  `dpop_bound_access_tokens`, or a resource with `dpop: :required`, never
  gets Bearer tokens.
  """

  alias Gatekeep.{Client, ClientAuth, Config, DPoP, Resource, Storage, Util}

  # Grants beyond authorization_code and refresh_token, each a Gatekeep.Grant.
  @extension_grants [Gatekeep.DeviceAuthorization]

  @typedoc """
  The HTTP request around the form parameters: its `Authorization` header and
  every `DPoP` header value.
  """
  @type http :: %{authorization: String.t() | nil, dpop: [String.t()]}

  @type error ::
          :invalid_client
          | :invalid_request
          | :invalid_grant
          | :invalid_scope
          | :invalid_target
          | :invalid_dpop_proof
          | :unauthorized_client
          | :unsupported_grant_type
          | :access_denied
          | :authorization_pending
          | :slow_down
          | :expired_token

  @doc """
  Handles a token request. Returns the token response body, or an OAuth
  error code. `invalid_client` is answered with 401, the others with 400.
  """
  @spec token(Config.t(), map(), http()) :: {:ok, map()} | {:error, error()}
  def token(%Config{} = config, params, http) do
    grant_type = params["grant_type"]

    with {:ok, client, method} <- authenticate(config, params, http),
         {:ok, handle} <- handler(config, grant_type),
         :ok <- Util.expect(Client.grant_allowed?(client, grant_type), :unauthorized_client),
         {:ok, jkt} <- dpop_key(config, client, http) do
      handle.(config, client, method, params, jkt)
    end
  end

  @doc """
  The extension grants (`Gatekeep.Grant` modules) that `config` turns on.
  """
  @spec grants(Config.t()) :: [module()]
  def grants(%Config{} = config), do: Enum.filter(@extension_grants, & &1.enabled?(config))

  defp handler(_config, "authorization_code"), do: {:ok, &exchange_code/5}
  defp handler(_config, "refresh_token"), do: {:ok, &refresh/5}

  defp handler(config, grant_type) do
    case Enum.find(grants(config), &(&1.grant_type() == grant_type)) do
      nil -> {:error, :unsupported_grant_type}
      module -> {:ok, &module.token/5}
    end
  end

  defp authenticate(config, params, http) do
    case ClientAuth.authenticate(config, params, http[:authorization]) do
      {:ok, client, method} -> {:ok, client, method}
      {:error, _reason} -> {:error, :invalid_client}
    end
  end

  # A proof is optional, except for a client that declares
  # `dpop_bound_access_tokens` (RFC 9449 §5.2).
  defp dpop_key(config, client, http) do
    case Map.get(http, :dpop, []) do
      [] ->
        if client.dpop_bound, do: {:error, :invalid_dpop_proof}, else: {:ok, nil}

      proofs ->
        request = %{method: "POST", url: Config.endpoint(config, :token)}

        case DPoP.verify(proofs, request, config) do
          {:ok, jkt} -> {:ok, jkt}
          {:error, _reason} -> {:error, :invalid_dpop_proof}
        end
    end
  end

  ## Authorization code

  defp exchange_code(config, client, method, params, jkt) do
    code = params["code"]
    hash = Util.hash(if is_binary(code), do: code, else: "")
    now = Util.now_dt()

    # The code stays locked until the transaction ends, so a concurrent reuse
    # waits and then finds the grant to revoke.
    Storage.call(config, :transaction, [
      fn ->
        case Storage.call(config, :consume_code, [hash, now]) do
          {:ok, row} ->
            redeem_code(config, row, client, method, params, jkt, now)

          :error ->
            revoke_reused_code(config, hash, client, method)
            {:error, :invalid_grant}
        end
      end
    ])
  end

  defp redeem_code(config, row, client, method, params, jkt, now) do
    resource = Config.resource(config, row.resource)

    with :ok <- Util.expect(row.client_id == client.client_id),
         :ok <- Util.expect(DateTime.compare(row.expires_at, now) == :gt),
         :ok <- Util.expect(row.redirect_uri == params["redirect_uri"]),
         :ok <- check_pkce(row.code_challenge, params["code_verifier"]),
         :ok <- Util.expect(is_nil(row.dpop_jkt) or row.dpop_jkt == jkt),
         :ok <- check_resource_usable(resource, client, method),
         :ok <- check_resource_param(params["resource"], resource),
         :ok <- check_dpop_required(resource, jkt) do
      refresh_token =
        if Client.grant_allowed?(client, "refresh_token"), do: Util.random_token("gkr_")

      {:ok, grant} =
        Storage.call(config, :insert_grant, [
          %{
            client_id: client.client_id,
            client_name: client.client_name,
            subject: row.subject,
            owner: row.owner,
            resource: resource.id,
            scopes: row.scopes,
            claims: row.claims || %{},
            grant_type: "authorization_code",
            refresh_token_hash: refresh_token && Util.hash(refresh_token),
            dpop_jkt: jkt,
            expires_at: Util.in_seconds(config.refresh_token_ttl)
          }
        ])

      :ok = Storage.call(config, :set_code_grant, [row.code_hash, grant.id])

      body = issue_access_token(config, grant, row.scopes, jkt)
      {:ok, if(refresh_token, do: Map.put(body, "refresh_token", refresh_token), else: body)}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_grant}
    end
  end

  defp check_pkce(challenge, verifier)
       when is_binary(verifier) and byte_size(verifier) in 43..128 do
    if verifier =~ ~r/\A[A-Za-z0-9\-._~]+\z/,
      do: Util.expect(Plug.Crypto.secure_compare(Gatekeep.JOSE.digest(verifier), challenge)),
      else: :error
  end

  defp check_pkce(_challenge, _verifier), do: :error

  @doc """
  `:ok` when `resource` is configured and enabled, and admits `client`
  authenticated with `method` (`Gatekeep.Resource.allows?/3`). A resource
  that is gone or turned off issues nothing. For `Gatekeep.Grant` modules.
  """
  @spec check_resource_usable(Resource.t() | nil, Client.t(), String.t()) :: :ok | :error
  def check_resource_usable(%Resource{enabled: true} = resource, client, method),
    do: Util.expect(Resource.allows?(resource, client, method))

  def check_resource_usable(_resource, _client, _method), do: :error

  # A token request may repeat the grant's resource (RFC 8707 §2.2), never
  # name another.
  defp check_resource_param(nil, _resource), do: :ok

  defp check_resource_param(param, resource) do
    if Util.same_url?(param, resource.id), do: :ok, else: {:error, :invalid_target}
  end

  @doc """
  `{:error, :invalid_dpop_proof}` when `resource` requires DPoP and the
  request had no proof. For `Gatekeep.Grant` modules.
  """
  @spec check_dpop_required(Resource.t(), String.t() | nil) :: :ok | {:error, :invalid_dpop_proof}
  def check_dpop_required(%Resource{dpop: :required}, nil), do: {:error, :invalid_dpop_proof}
  def check_dpop_required(_resource, _jkt), do: :ok

  # Only the client the code was issued to, authenticated the way its
  # resource requires, revokes the grant by reusing the code. Another client
  # gets `invalid_grant` and changes nothing.
  defp revoke_reused_code(config, hash, client, method) do
    with {:ok, %{client_id: client_id, grant_id: grant_id} = row} when not is_nil(grant_id) <-
           Storage.call(config, :get_code, [hash]),
         true <- client_id == client.client_id,
         :ok <- check_method(config, row.resource, client, method) do
      Storage.call(config, :revoke_grant, [grant_id, Util.now_dt()])
    end
  end

  defp check_method(config, resource_id, client, method) do
    case Config.resource(config, resource_id) do
      %Resource{} = resource -> Util.expect(Resource.allows?(resource, client, method))
      nil -> :error
    end
  end

  ## Refresh

  defp refresh(config, client, method, params, jkt) do
    token = params["refresh_token"]
    hash = Util.hash(if is_binary(token), do: token, else: "")

    # The row lock makes concurrent refreshes with one token take turns: the
    # second finds the token rotated away, which is reuse.
    Storage.call(config, :transaction, [
      fn ->
        case Storage.call(config, :lock_grant_by_refresh_token, [hash]) do
          {:ok, grant} ->
            refresh_grant(config, grant, hash, client, method, params, jkt)

          :error ->
            revoke_reused_refresh_token(config, hash, client, method)
            {:error, :invalid_grant}
        end
      end
    ])
  end

  defp refresh_grant(config, grant, hash, client, method, params, jkt) do
    resource = Config.resource(config, grant.resource)

    with :ok <- Util.expect(grant.client_id == client.client_id),
         :ok <- check_resource_usable(resource, client, method),
         :ok <- Util.expect(active?(grant)),
         :ok <- Util.expect(is_nil(grant.dpop_jkt) or grant.dpop_jkt == jkt),
         :ok <- check_dpop_required(resource, jkt),
         {:ok, scopes} <- narrow_scopes(params["scope"], grant.scopes),
         :ok <- check_resource_param(params["resource"], resource),
         {:ok, refresh_token} <- maybe_rotate(config, resource, grant, hash) do
      body = issue_access_token(config, grant, scopes, jkt)
      {:ok, if(refresh_token, do: Map.put(body, "refresh_token", refresh_token), else: body)}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_grant}
    end
  end

  defp active?(%{revoked_at: nil, expires_at: expires_at}),
    do: is_nil(expires_at) or DateTime.compare(expires_at, DateTime.utc_now()) == :gt

  defp active?(_grant), do: false

  defp narrow_scopes(nil, granted), do: {:ok, granted}

  defp narrow_scopes(scope, granted) do
    case Util.split_scope(scope) do
      [] -> {:ok, granted}
      scopes -> if scopes -- granted == [], do: {:ok, scopes}, else: {:error, :invalid_scope}
    end
  end

  defp maybe_rotate(config, %Resource{rotate_refresh_tokens: true}, grant, hash) do
    refresh_token = Util.random_token("gkr_")

    case Storage.call(config, :rotate_refresh_token, [
           grant.id,
           hash,
           Util.hash(refresh_token),
           Util.now_dt()
         ]) do
      :ok ->
        {:ok, refresh_token}

      # The swap missed under the lock: the token is being used twice.
      :error ->
        Storage.call(config, :revoke_grant, [grant.id, Util.now_dt()])
        :error
    end
  end

  defp maybe_rotate(_config, _resource, _grant, _hash), do: {:ok, nil}

  # Any refresh token a grant rotated away revokes the grant, when the
  # grant's own client presents it, authenticated the way its resource
  # requires. Another client gets `invalid_grant` and changes nothing.
  defp revoke_reused_refresh_token(config, hash, client, method) do
    with {:ok, grant} <- Storage.call(config, :find_grant_by_consumed_refresh_token, [hash]),
         true <- grant.client_id == client.client_id,
         :ok <- check_method(config, grant.resource, client, method) do
      Storage.call(config, :revoke_grant, [grant.id, Util.now_dt()])
    end
  end

  ## For grant modules

  @doc """
  The resource a token request is for: the `resource` parameter, or the
  resource its scopes name, or `:default_resource`. For `Gatekeep.Grant`
  modules.
  """
  @spec grant_resource(Config.t(), term(), term()) ::
          {:ok, Resource.t()} | {:error, :invalid_target | :invalid_scope}
  def grant_resource(config, resource_param, scope) do
    case Gatekeep.Authorization.select_resource(config, resource_param, scope) do
      {:ok, resource} -> {:ok, resource}
      {:error, "invalid_target"} -> {:error, :invalid_target}
      {:error, _} -> {:error, :invalid_scope}
    end
  end

  @doc """
  The scopes a token request gets at `resource`: the requested ones (or the
  resource's defaults), limited to what `client` may have. For `Gatekeep.Grant`
  modules.
  """
  @spec client_scopes(Resource.t(), Client.t(), term()) ::
          {:ok, [String.t()]} | {:error, :invalid_scope}
  def client_scopes(resource, client, scope) do
    case Gatekeep.Authorization.requested_scopes(resource, client, scope) do
      {:ok, scopes} -> {:ok, scopes}
      {:error, _} -> {:error, :invalid_scope}
    end
  end

  ## Access tokens

  @doc """
  Issues an access token under `grant`, bound to the DPoP key `jkt` if any,
  and returns the token response body. For `Gatekeep.Grant` modules.
  """
  @spec issue_access_token(Config.t(), Storage.grant(), [String.t()], String.t() | nil) :: map()
  def issue_access_token(config, grant, scopes, jkt) do
    {token, expires_at} = mint(config, grant, scopes, jkt)

    :ok =
      Storage.call(config, :insert_access_token, [
        %{
          token_hash: Util.hash(token),
          grant_id: grant.id,
          client_id: grant.client_id,
          subject: grant.subject,
          resource: grant.resource,
          scopes: scopes,
          dpop_jkt: jkt,
          expires_at: expires_at
        }
      ])

    %{
      "access_token" => token,
      "token_type" => if(jkt, do: "DPoP", else: "Bearer"),
      "expires_in" => config.access_token_ttl,
      "scope" => Enum.join(scopes, " ")
    }
  end

  defp mint(%Config{access_token_format: :opaque} = config, _grant, _scopes, _jkt) do
    {Util.random_token("gka_"), Util.in_seconds(config.access_token_ttl)}
  end

  # RFC 9068 JWT access tokens. They are stored by hash like opaque ones, so
  # revocation works the same; other servers can verify them offline with the
  # JWKS endpoint, until they expire.
  defp mint(%Config{access_token_format: :jwt} = config, grant, scopes, jkt) do
    now = Util.now()
    exp = now + config.access_token_ttl

    claims =
      %{
        "iss" => config.issuer,
        "sub" => grant.subject,
        "aud" => grant.resource,
        "client_id" => grant.client_id,
        "scope" => Enum.join(scopes, " "),
        "iat" => now,
        "exp" => exp,
        "jti" => Util.random_token("")
      }
      |> then(&if(jkt, do: Map.put(&1, "cnf", %{"jkt" => jkt}), else: &1))

    case Gatekeep.Signer.sign(config, %{"typ" => "at+jwt"}, claims) do
      {:ok, jwt} -> {jwt, DateTime.from_unix!(exp)}
      {:error, reason} -> raise "Gatekeep signer could not sign an access token: #{inspect(reason)}"
    end
  end

  ## Revocation

  @doc """
  Revocation (RFC 7009). Revoking a refresh token revokes its grant, and with
  it every access token issued under it. Revoking an access token revokes
  that token. Unknown tokens, and tokens of other clients, succeed without
  effect, as RFC 7009 §2.2 asks. Only `invalid_client` is an error.
  """
  @spec revoke(Config.t(), map(), http()) :: :ok | {:error, :invalid_client}
  def revoke(%Config{} = config, params, http) do
    with {:ok, client, _method} <- authenticate(config, params, http) do
      if is_binary(params["token"]), do: revoke_token(config, client, Util.hash(params["token"]))
      :ok
    end
  end

  defp revoke_token(config, client, hash) do
    now = Util.now_dt()

    with :error <- Storage.call(config, :lock_grant_by_refresh_token, [hash]),
         {:ok, token} <- Storage.call(config, :get_access_token, [hash]) do
      if token.client_id == client.client_id,
        do: Storage.call(config, :revoke_access_token, [hash, now])
    else
      {:ok, %{client_id: client_id} = grant} when client_id == client.client_id ->
        Storage.call(config, :revoke_grant, [grant.id, now])

      _ ->
        :ok
    end
  end
end
