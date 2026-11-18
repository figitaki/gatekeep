defmodule Gatekeep.DeviceAuthorization do
  @moduledoc """
  The device authorization grant (RFC 8628), for clients that can't open a
  browser on the user's machine or receive a redirect, such as a
  command-line tool over SSH.

  1. The client posts to the device authorization endpoint
     (`/oauth/device_authorization`) and gets a `device_code`, a short
     `user_code` such as `WDJB-MJHT`, and the `verification_uri` to show.
  2. The user opens that page on any device, signs in, and enters the code.
     The page is the app's: it calls `lookup/2` to show the client and the
     scopes, then `approve/3` or `deny/2`.
  3. Meanwhile the client polls the token endpoint with
     `grant_type=urn:ietf:params:oauth:grant-type:device_code` and gets
     `authorization_pending` until the user decides, then the tokens or
     `access_denied`. Polling faster than `interval` gets `slow_down`, and
     the interval grows by 5 seconds for that code (RFC 8628 §3.5). After
     `:device_code_ttl` the code is `expired_token`.

  Set `:device_verification_uri` to turn the grant on. A client may use it
  when its `grant_types` list it: pre-registered clients, or metadata
  document clients that declare it. Registered clients can't.

  A device code is redeemed once. Presenting it again, after it got tokens,
  revokes the grant those tokens belong to, as reusing an authorization code
  does.

  ## The verification page

  Device flows invite phishing: anyone can start one and send the link to
  someone else. The page should say which client asks and for what, take
  the decision with a POST protected against CSRF (never approve on a GET,
  even with `verification_uri_complete`), and limit how many wrong codes a
  person may try (RFC 8628 §5.1): user codes have about 34 bits of entropy.
  """

  @behaviour Gatekeep.Grant

  alias Gatekeep.{Client, ClientAuth, Clients, Config, Resource, Storage, TokenEndpoint, Util}

  @grant_type "urn:ietf:params:oauth:grant-type:device_code"
  # Consonants only, so codes spell no words and survive being read aloud
  # (RFC 8628 §6.1).
  @alphabet ~c"BCDFGHJKLMNPQRSTVWXZ"
  @slow_down_seconds 5

  @typedoc """
  A pending request, for the verification page:

    * `user_code` - the code, formatted as `XXXX-XXXX`.
    * `client` - the `Gatekeep.Client`; show `Gatekeep.Client.label/1`.
    * `resource` - the `Gatekeep.Resource` the tokens will be for.
    * `scopes` - the requested scopes, which the user may narrow.
    * `scope_descriptions` - descriptions of those scopes for the page.
    * `expires_at` - when the code expires, so the page can count down.
  """
  @type request :: %{
          user_code: String.t(),
          client: Client.t(),
          resource: Resource.t(),
          scopes: [String.t()],
          scope_descriptions: %{String.t() => String.t()},
          expires_at: DateTime.t()
        }

  @impl true
  def grant_type, do: @grant_type

  @impl true
  def enabled?(%Config{device_verification_uri: uri}), do: not is_nil(uri)

  @impl true
  def metadata(config),
    do: %{"device_authorization_endpoint" => Config.endpoint(config, :device_authorization)}

  @doc """
  Handles a device authorization request (RFC 8628 §3.1): authenticates the
  client the way the token endpoint does, checks the resource and scopes,
  and returns the response body, or an OAuth error code (`invalid_client`
  is answered with 401, the others with 400). `{:error, :not_found}` when
  the grant is off.
  """
  @spec authorize(Config.t(), map(), TokenEndpoint.http()) ::
          {:ok, map()} | {:error, TokenEndpoint.error() | :not_found}
  def authorize(%Config{} = config, params, http) do
    with :ok <- Util.expect(enabled?(config), :not_found),
         {:ok, client, method} <- authenticate(config, params, http),
         :ok <- Util.expect(Client.grant_allowed?(client, @grant_type), :unauthorized_client),
         {:ok, resource} <-
           TokenEndpoint.grant_resource(config, params["resource"], params["scope"]),
         :ok <-
           Util.expect(
             TokenEndpoint.check_resource_usable(resource, client, method) == :ok,
             :unauthorized_client
           ),
         {:ok, scopes} <- TokenEndpoint.client_scopes(resource, client, params["scope"]) do
      device_code = Util.random_token("gkd_")

      user_code =
        insert(config, %{
          device_code_hash: Util.hash(device_code),
          client_id: client.client_id,
          client_name: client.client_name,
          resource: resource.id,
          scopes: scopes,
          interval: config.device_poll_interval,
          expires_at: Util.in_seconds(config.device_code_ttl)
        })

      verification_uri = Config.device_verification_uri(config)

      {:ok,
       %{
         "device_code" => device_code,
         "user_code" => user_code,
         "verification_uri" => verification_uri,
         "verification_uri_complete" => with_query(verification_uri, user_code: user_code),
         "expires_in" => config.device_code_ttl,
         "interval" => config.device_poll_interval
       }}
    end
  end

  defp authenticate(config, params, http) do
    case ClientAuth.authenticate(config, params, http[:authorization]) do
      {:ok, client, method} -> {:ok, client, method}
      {:error, _reason} -> {:error, :invalid_client}
    end
  end

  # A new user code can collide with a live one; try another.
  defp insert(config, row, attempts \\ 3) do
    user_code = new_user_code()
    row = Map.put(row, :user_code_hash, hash_user_code(user_code))

    case Storage.call(config, :insert_device_code, [row]) do
      :ok -> user_code
      {:error, :conflict} when attempts > 1 -> insert(config, row, attempts - 1)
    end
  end

  defp new_user_code do
    <<a::binary-size(4), b::binary-size(4)>> = random_letters(8, [])
    a <> "-" <> b
  end

  # Rejection sampling: 240 is the largest multiple of 20 under 256.
  defp random_letters(0, acc), do: List.to_string(acc)

  defp random_letters(n, acc) do
    case :crypto.strong_rand_bytes(1) do
      <<byte>> when byte < 240 -> random_letters(n - 1, [Enum.at(@alphabet, rem(byte, 20)) | acc])
      _ -> random_letters(n, acc)
    end
  end

  # What people type: any case, with or without the dash or spaces.
  defp normalize(user_code), do: user_code |> String.upcase() |> String.replace(~r/[^A-Z]/, "")

  defp hash_user_code(user_code), do: Util.hash(normalize(user_code))

  defp with_query(url, query) do
    uri = URI.parse(url)

    URI.to_string(%{
      uri
      | query: Enum.join(Enum.reject([uri.query, URI.encode_query(query)], &is_nil/1), "&")
    })
  end

  ## The verification page

  @doc """
  The pending request with `user_code`, for the verification page.
  `:invalid_user_code` when there is none or it was decided already;
  `:expired_user_code` when it waited too long.
  """
  @spec lookup(Config.t(), term()) ::
          {:ok, request()} | {:error, :invalid_user_code | :expired_user_code}
  def lookup(%Config{} = config, user_code) when is_binary(user_code) do
    with {:ok, row} <- Storage.call(config, :get_device_code, [hash_user_code(user_code)]),
         :ok <- Util.expect(row.status == "pending"),
         {:ok, client} <- Clients.fetch(config, row.client_id),
         %Resource{enabled: true} = resource <- Config.resource(config, row.resource) do
      if DateTime.compare(row.expires_at, DateTime.utc_now()) == :gt do
        <<a::binary-size(4), b::binary>> = normalize(user_code)

        {:ok,
         %{
           user_code: a <> "-" <> b,
           client: client,
           resource: resource,
           scopes: row.scopes,
           scope_descriptions: Map.take(resource.scope_descriptions, row.scopes),
           expires_at: row.expires_at
         }}
      else
        {:error, :expired_user_code}
      end
    else
      _ -> {:error, :invalid_user_code}
    end
  end

  def lookup(_config, _user_code), do: {:error, :invalid_user_code}

  @doc """
  The user approved the request with `user_code`. The device's next poll
  gets the tokens. Takes the options of `Gatekeep.Authorization.approve/3`:
  `:subject` (required), `:scopes`, `:owner`, and `:claims`.
  """
  @spec approve(Config.t(), String.t(), keyword()) ::
          :ok | {:error, :invalid_user_code | :expired_user_code | :invalid_scopes}
  def approve(%Config{} = config, user_code, opts) do
    subject = Keyword.fetch!(opts, :subject)

    with {:ok, request} <- lookup(config, user_code),
         {:ok, granted} <- granted_scopes(request.scopes, opts) do
      decide(config, user_code, %{
        status: "approved",
        subject: to_string(subject),
        owner: opts[:owner] && to_string(opts[:owner]),
        claims: Keyword.get(opts, :claims, %{}),
        scopes: granted
      })
    end
  end

  @doc "The user denied the request with `user_code`. The device's next poll gets `access_denied`."
  @spec deny(Config.t(), String.t()) :: :ok | {:error, :invalid_user_code | :expired_user_code}
  def deny(%Config{} = config, user_code) do
    with {:ok, _request} <- lookup(config, user_code) do
      decide(config, user_code, %{status: "denied"})
    end
  end

  # The decision applies only to a pending, unexpired code, so of two
  # concurrent decisions one wins.
  defp decide(config, user_code, changes) do
    case Storage.call(config, :decide_device_code, [
           hash_user_code(user_code),
           changes,
           Util.now_dt()
         ]) do
      {:ok, _row} -> :ok
      :error -> {:error, :invalid_user_code}
    end
  end

  defp granted_scopes(requested, opts) do
    granted = opts |> Keyword.get(:scopes, requested) |> List.wrap()

    if granted == [] or granted -- requested != [],
      do: {:error, :invalid_scopes},
      else: {:ok, Enum.filter(requested, &(&1 in granted))}
  end

  ## Polling

  @impl true
  def token(config, client, method, params, jkt) do
    code = params["device_code"]
    hash = Util.hash(if is_binary(code), do: code, else: "")
    now = Util.now_dt()

    # The row lock makes polls of one code take turns, so the interval
    # check and the redemption see each other's writes.
    Storage.call(config, :transaction, [
      fn ->
        case Storage.call(config, :lock_device_code, [hash]) do
          {:ok, %{client_id: client_id} = row} when client_id == client.client_id ->
            poll(config, row, client, method, params, jkt, now)

          _ ->
            {:error, :invalid_grant}
        end
      end
    ])
  end

  defp poll(config, row, client, method, params, jkt, now) do
    resource = Config.resource(config, row.resource)

    cond do
      TokenEndpoint.check_resource_usable(resource, client, method) != :ok ->
        {:error, :invalid_grant}

      not is_nil(row.consumed_at) ->
        if row.grant_id, do: Storage.call(config, :revoke_grant, [row.grant_id, now])
        {:error, :invalid_grant}

      DateTime.compare(row.expires_at, now) != :gt ->
        {:error, :expired_token}

      too_soon?(row, now) ->
        update(config, row, %{interval: row.interval + @slow_down_seconds, last_polled_at: now})
        {:error, :slow_down}

      row.status == "pending" ->
        update(config, row, %{last_polled_at: now})
        {:error, :authorization_pending}

      row.status == "denied" ->
        update(config, row, %{last_polled_at: now})
        {:error, :access_denied}

      true ->
        redeem(config, row, client, resource, params, jkt, now)
    end
  end

  defp too_soon?(%{last_polled_at: nil}, _now), do: false
  defp too_soon?(row, now), do: DateTime.diff(now, row.last_polled_at) < row.interval

  defp redeem(config, row, client, resource, params, jkt, now) do
    with :ok <- check_resource_param(params["resource"], resource),
         :ok <- TokenEndpoint.check_dpop_required(resource, jkt) do
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
            grant_type: @grant_type,
            refresh_token_hash: refresh_token && Util.hash(refresh_token),
            dpop_jkt: jkt,
            expires_at: Util.in_seconds(config.refresh_token_ttl)
          }
        ])

      update(config, row, %{consumed_at: now, last_polled_at: now, grant_id: grant.id})

      body = TokenEndpoint.issue_access_token(config, grant, row.scopes, jkt)
      {:ok, if(refresh_token, do: Map.put(body, "refresh_token", refresh_token), else: body)}
    end
  end

  # A token request may repeat the resource (RFC 8707 §2.2), never name another.
  defp check_resource_param(nil, _resource), do: :ok

  defp check_resource_param(param, resource),
    do: Util.expect(Util.same_url?(param, resource.id), :invalid_target)

  defp update(config, row, changes),
    do: :ok = Storage.call(config, :update_device_code, [row.device_code_hash, changes])
end
