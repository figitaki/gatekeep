defmodule Gatekeep.Clients do
  @moduledoc """
  Resolves a `client_id` to a `Gatekeep.Client`:

    * a client listed under `:clients` in config;
    * a `gkc_` ID, registered through dynamic client registration and kept by
      the storage;
    * an HTTPS URL naming a client ID metadata document, which is fetched,
      checked, and cached with the key set at its `jwks_uri`.

  Metadata documents are cached for `:client_cache_seconds`, so a key removed
  from `jwks_uri` stops being trusted within that time. An unknown `kid`
  refetches the key set at most once every 30 seconds per client, and failed
  fetches are remembered for 30 seconds too, so forged requests can't make
  Gatekeep flood a client's server. Concurrent requests for one client share
  a single fetch.
  """

  alias Gatekeep.{Cache, Client, Config, Fetcher, JOSE, Storage}

  @refetch_interval 30
  @auth_methods ["none", "private_key_jwt"]

  @doc "The client named `client_id`, or why it can't be used."
  @spec fetch(Config.t(), term()) :: {:ok, Client.t()} | {:error, atom()}
  def fetch(%Config{} = config, client_id) when is_binary(client_id) and client_id != "" do
    cond do
      client_id in config.blocked_clients ->
        {:error, :client_refused}

      static = Enum.find(config.clients, &(&1.client_id == client_id)) ->
        {:ok, static}

      String.starts_with?(client_id, "gkc_") ->
        registered(config, client_id)

      valid_client_id?(client_id) ->
        cached_document(config, client_id)

      true ->
        {:error, :invalid_client_id}
    end
  end

  def fetch(_config, _client_id), do: {:error, :invalid_client_id}

  defp registered(config, client_id) do
    case Storage.call(config, :get_client, [client_id]) do
      {:ok, record} ->
        {:ok,
         %Client{
           client_id: record.client_id,
           client_name: record.client_name,
           redirect_uris: record.redirect_uris,
           kind: :registered,
           auth_methods: ["none"],
           grant_types: ["authorization_code", "refresh_token"]
         }}

      :error ->
        {:error, :unknown_client}
    end
  end

  defp cached_document(config, client_id) do
    key = {:client, client_id}

    with :miss <- lookup(config, key) do
      Cache.single_flight(config.name, key, fn ->
        with :miss <- lookup(config, key), do: load(config, client_id)
      end)
    end
  end

  defp lookup(config, key) do
    case Cache.lookup(config.name, key) do
      {:ok, result, _fetched_at} -> result
      :miss -> :miss
    end
  end

  @doc "Drops the cached metadata and keys of `client_id`, such as after a key leak."
  @spec forget(Config.t(), String.t()) :: :ok
  def forget(%Config{} = config, client_id) do
    Cache.delete(config.name, {:client, client_id})
    :ok
  end

  @doc """
  The key named `kid` in the client's key set. Refetches a metadata document
  client's key set once per interval when the `kid` is unknown.
  """
  @spec key(Config.t(), Client.t(), term()) :: {:ok, map()} | {:error, :unknown_key}
  def key(config, %Client{keys: keys} = client, kid) when is_binary(kid) do
    case find_key(keys, kid) do
      nil when client.kind == :metadata_document and is_binary(client.jwks_uri) ->
        Cache.single_flight(config.name, {:client, client.client_id}, fn ->
          refetch_key(config, client.client_id, kid)
        end)

      nil ->
        {:error, :unknown_key}

      key ->
        {:ok, key}
    end
  end

  def key(_config, _client, _kid), do: {:error, :unknown_key}

  defp refetch_key(config, client_id, kid) do
    now = Gatekeep.Util.now()
    key = {:client, client_id}

    case Cache.lookup(config.name, key) do
      {:ok, {:ok, cached}, fetched_at} ->
        cond do
          found = find_key(cached.keys, kid) ->
            {:ok, found}

          now - fetched_at >= @refetch_interval ->
            client =
              case fetch_keys(config, cached.jwks_uri) do
                {:ok, keys} -> %{cached | keys: keys}
                {:error, _} -> cached
              end

            Cache.update(config.name, key, {:ok, client}, now)
            if found = find_key(client.keys, kid), do: {:ok, found}, else: {:error, :unknown_key}

          true ->
            {:error, :unknown_key}
        end

      _ ->
        {:error, :unknown_key}
    end
  end

  defp find_key(keys, kid), do: Enum.find(keys, &(&1["kid"] == kid))

  defp load(config, client_id) do
    result =
      with {:ok, metadata} <- fetch_document(config, client_id),
           {:ok, client} <- check_metadata(client_id, metadata),
           {:ok, keys} <- maybe_fetch_keys(config, client.jwks_uri) do
        {:ok, %{client | keys: keys}}
      end

    ttl = if match?({:ok, _}, result), do: config.client_cache_seconds, else: @refetch_interval
    Cache.put(config.name, {:client, client_id}, result, ttl, config.client_cache_size)
    result
  end

  defp fetch_document(config, url) do
    case Fetcher.fetch_json(url, config) do
      {:ok, json} -> {:ok, json}
      {:error, :invalid_json} -> {:error, :invalid_client_metadata}
      {:error, _} -> {:error, :client_metadata_unavailable}
    end
  end

  # The document must name itself, and its keys and redirect URIs must be on
  # its own host (or loopback redirects), so whoever controls the domain
  # controls the client.
  defp check_metadata(client_id, %{"client_id" => client_id} = metadata) do
    host = URI.parse(client_id).host
    jwks_uri = metadata["jwks_uri"]
    redirect_uris = Map.get(metadata, "redirect_uris", [])
    name = metadata["client_name"]
    auth_methods = auth_methods(metadata, is_binary(jwks_uri))

    grant_types =
      case metadata["grant_types"] do
        list when is_list(list) -> Enum.filter(list, &is_binary/1)
        # No `grant_types`: the interactive grants, and the identity
        # assertion grant, which the IdP vouches for per client (its
        # `client_id` claim must name this client).
        _ -> ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"]
      end

    cond do
      not (is_nil(jwks_uri) or https_on_host?(jwks_uri, host)) ->
        {:error, :invalid_client_metadata}

      not is_list(redirect_uris) or
          not Enum.all?(redirect_uris, &(https_on_host?(&1, host) or loopback_redirect?(&1))) ->
        {:error, :invalid_client_metadata}

      auth_methods == [] ->
        {:error, :invalid_client_metadata}

      true ->
        {:ok,
         %Client{
           client_id: client_id,
           client_name: if(is_binary(name), do: String.slice(name, 0, 120)),
           kind: :metadata_document,
           jwks_uri: jwks_uri,
           redirect_uris: redirect_uris,
           auth_methods: auth_methods,
           grant_types: grant_types,
           dpop_bound: metadata["dpop_bound_access_tokens"] == true
         }}
    end
  end

  defp check_metadata(_client_id, _metadata), do: {:error, :invalid_client_metadata}

  # The methods both sides support. The plural field lists every method the
  # client can use; without it the singular one is binding, and without
  # either a client with keys uses them. `private_key_jwt` needs a key set.
  defp auth_methods(metadata, has_keys?) do
    declared =
      case metadata do
        %{"token_endpoint_auth_methods_supported" => methods} when is_list(methods) -> methods
        %{"token_endpoint_auth_method" => method} when is_binary(method) -> [method]
        _ when has_keys? -> ["private_key_jwt"]
        _ -> ["none"]
      end

    Enum.filter(@auth_methods, &(&1 in declared and (&1 == "none" or has_keys?)))
  end

  defp maybe_fetch_keys(_config, nil), do: {:ok, []}
  defp maybe_fetch_keys(config, jwks_uri), do: fetch_keys(config, jwks_uri)

  @doc false
  def fetch_keys(config, jwks_uri) do
    case Fetcher.fetch_json(jwks_uri, config) do
      {:ok, %{"keys" => keys}} when is_list(keys) ->
        {:ok, Enum.filter(keys, &(is_map(&1) and JOSE.public_key?(&1)))}

      _ ->
        {:error, :invalid_jwks}
    end
  end

  @doc "A client ID metadata URL: HTTPS with a path, and no fragment, query, or credentials."
  @spec valid_client_id?(term()) :: boolean()
  def valid_client_id?(client_id) when is_binary(client_id) do
    case URI.parse(client_id) do
      %URI{scheme: "https", host: host, path: path, fragment: nil, query: nil, userinfo: nil}
      when is_binary(host) and host != "" and is_binary(path) and path != "/" ->
        not String.contains?(path, ["/./", "/../"])

      _ ->
        false
    end
  end

  def valid_client_id?(_), do: false

  defp https_on_host?(url, host) when is_binary(url),
    do: match?(%URI{scheme: "https", host: ^host, fragment: nil, userinfo: nil}, URI.parse(url))

  defp https_on_host?(_url, _host), do: false

  @doc """
  A loopback redirect URI (RFC 8252 §7.3): http and a loopback IP literal, or
  `localhost`, which Claude Code and other MCP clients register.
  """
  @spec loopback_redirect?(term()) :: boolean()
  def loopback_redirect?(url) when is_binary(url) do
    match?(
      %URI{scheme: "http", host: host, fragment: nil, userinfo: nil}
      when host in ["127.0.0.1", "::1", "localhost"],
      URI.parse(url)
    )
  end

  def loopback_redirect?(_url), do: false
end
