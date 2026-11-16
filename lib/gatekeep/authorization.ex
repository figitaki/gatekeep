defmodule Gatekeep.Authorization do
  @moduledoc """
  The authorization endpoint (OAuth 2.1 §4.1): checking a request, and
  turning the user's decision into the redirect back to the client.

  `Gatekeep.Plug.Authorize` calls `check/2` and hands valid requests to the
  `Gatekeep.Consent` module. That module calls `approve/3` or `deny/2` once
  the user decides.

  Every redirect back to the client carries `iss` (RFC 9207), errors
  included. Errors about the client or its redirect URI never redirect, and
  neither do errors of clients registered through dynamic client
  registration, since anyone can register any redirect URI: redirecting them
  would make the endpoint an open redirector (OAuth 2.1 §7.12.2).
  """

  alias Gatekeep.{Client, Clients, Config, Resource, Storage, Util}

  @params ~w(response_type client_id redirect_uri scope state code_challenge code_challenge_method dpop_jkt resource)

  @type request :: %{
          client: Client.t(),
          resource: Resource.t(),
          scopes: [String.t()],
          scope_descriptions: %{String.t() => String.t()},
          redirect_uri: String.t(),
          state: String.t() | nil,
          code_challenge: String.t(),
          dpop_jkt: String.t() | nil,
          params: %{String.t() => String.t()}
        }

  @doc """
  Checks an authorization request.

    * `{:ok, request}` - valid; ask the user.
    * `{:redirect, url}` - invalid, and the client should hear about it:
      redirect the browser to `url`, which carries the error and `iss`.
    * `{:error, reason}` - invalid, and must not redirect. Show an error page.
      `reason` is `:invalid_client`, `:invalid_redirect_uri`, or
      `:invalid_request`.
  """
  @spec check(Config.t(), map()) ::
          {:ok, request()} | {:redirect, String.t()} | {:error, atom()}
  def check(%Config{} = config, params) when is_map(params) do
    with {:ok, client} <- fetch_client(config, params["client_id"]),
         :ok <- check_redirect_uri(client, params["redirect_uri"]) do
      base = %{
        client: client,
        redirect_uri: params["redirect_uri"],
        state: string(params["state"])
      }

      case check_params(config, client, params) do
        {:ok, request} ->
          {:ok,
           Map.merge(base, request)
           |> Map.put(:params, Map.take(params, @params))}

        {:error, error} ->
          error_redirect(config, base, error)
      end
    end
  end

  defp fetch_client(config, client_id) do
    case Clients.fetch(config, client_id) do
      {:ok, client} -> {:ok, client}
      {:error, _} -> {:error, :invalid_client}
    end
  end

  defp check_params(config, client, params) do
    challenge = params["code_challenge"]
    dpop_jkt = params["dpop_jkt"]

    cond do
      params["response_type"] != "code" ->
        {:error, "unsupported_response_type"}

      not Client.grant_allowed?(client, "authorization_code") ->
        {:error, "unauthorized_client"}

      not (is_binary(challenge) and challenge =~ ~r/\A[A-Za-z0-9_-]{43}\z/) or
          params["code_challenge_method"] != "S256" ->
        {:error, "invalid_request"}

      # RFC 9449 §10: an optional SHA-256 JWK thumbprint the code is bound to.
      not (is_nil(dpop_jkt) or (is_binary(dpop_jkt) and dpop_jkt =~ ~r/\A[A-Za-z0-9_-]{43}\z/)) ->
        {:error, "invalid_request"}

      true ->
        with {:ok, resource} <- select_resource(config, params["resource"], params["scope"]),
             :ok <- check_client_method(resource, client),
             {:ok, scopes} <- requested_scopes(resource, client, params["scope"]) do
          {:ok,
           %{
             resource: resource,
             scopes: scopes,
             scope_descriptions: Map.take(resource.scope_descriptions, scopes),
             code_challenge: challenge,
             dpop_jkt: dpop_jkt
           }}
        end
    end
  end

  @doc false
  # A named resource must be one this issuer serves. Without one, the
  # resource whose scopes the request names, or else the default resource.
  def select_resource(config, resource_param, scope) do
    enabled = Config.enabled_resources(config)

    cond do
      is_binary(resource_param) ->
        case Enum.find(enabled, &Util.same_url?(resource_param, &1.id)) do
          nil -> {:error, "invalid_target"}
          resource -> {:ok, resource}
        end

      not is_nil(resource_param) ->
        {:error, "invalid_target"}

      named =
          Util.split_scope(scope) != [] &&
            Enum.find(enabled, &match?({:ok, _}, Resource.parse_scopes(&1, scope))) ->
        {:ok, named}

      default =
          config.default_resource &&
            Enum.find(enabled, &Util.same_url?(config.default_resource, &1.id)) ->
        {:ok, default}

      match?([_], enabled) and Util.split_scope(scope) == [] ->
        {:ok, hd(enabled)}

      true ->
        {:error, "invalid_scope"}
    end
  end

  # A client must be able to authenticate the way the resource needs.
  defp check_client_method(resource, client) do
    if Enum.any?(client.auth_methods, &(&1 in resource.client_auth_methods)),
      do: :ok,
      else: {:error, "unauthorized_client"}
  end

  @doc false
  def requested_scopes(resource, client, scope) do
    with {:ok, scopes} <- Resource.parse_scopes(resource, scope),
         scopes = allowed_for_client(scopes, client, scope),
         true <- scopes != [] do
      {:ok, scopes}
    else
      _ -> {:error, "invalid_scope"}
    end
  end

  # A client limited to some scopes gets the others only if it didn't ask
  # for them explicitly; asking for a forbidden scope is an error.
  defp allowed_for_client(scopes, %Client{scopes: nil}, _scope), do: scopes

  defp allowed_for_client(scopes, %Client{scopes: allowed}, scope) do
    if Util.split_scope(scope) != [] and scopes -- allowed != [],
      do: [],
      else: Enum.filter(scopes, &(&1 in allowed))
  end

  # Exact match, except the port of a loopback redirect URI (RFC 8252 §7.3).
  defp check_redirect_uri(%Client{redirect_uris: uris}, redirect_uri)
       when is_binary(redirect_uri) do
    matches? =
      Enum.any?(uris, fn registered ->
        registered == redirect_uri or
          (Clients.loopback_redirect?(registered) and Clients.loopback_redirect?(redirect_uri) and
             without_port(registered) == without_port(redirect_uri))
      end)

    if matches?, do: :ok, else: {:error, :invalid_redirect_uri}
  end

  defp check_redirect_uri(_client, _uri), do: {:error, :invalid_redirect_uri}

  defp without_port(url) do
    uri = URI.parse(url)
    {uri.scheme, uri.host, uri.path, uri.query}
  end

  defp error_redirect(_config, %{client: %Client{kind: :registered}}, _error),
    do: {:error, :invalid_request}

  defp error_redirect(config, request, error),
    do: {:redirect, callback_url(config, request, error: error)}

  @doc """
  The user approved `request`. Stores a one-time code and returns the
  redirect back to the client.

  Options:

    * `:subject` (required) - who the tokens act for, as a string, such as
      `"user:42"`. Resource servers see it as `Gatekeep.Token.subject`.
    * `:scopes` - the scopes the user granted, a subset of `request.scopes`
      (default: all of them). An empty or wider set is refused.
    * `:owner` - who manages the grant, for `Gatekeep.list_grants/2`, when it
      differs from the subject (such as the person behind an agent identity).
    * `:claims` - a map of extra data kept with the grant and given to
      resource servers as `Gatekeep.Token.claims`.
  """
  @spec approve(Config.t(), request(), keyword()) :: {:ok, String.t()} | {:error, :invalid_scopes}
  def approve(%Config{} = config, request, opts) do
    subject = Keyword.fetch!(opts, :subject)
    granted = opts |> Keyword.get(:scopes, request.scopes) |> List.wrap()
    granted = Enum.filter(request.scopes, &(&1 in granted))

    if granted == [] or
         (Keyword.has_key?(opts, :scopes) and List.wrap(opts[:scopes]) -- request.scopes != []) do
      {:error, :invalid_scopes}
    else
      code = Util.random_token("gkc_code_")

      :ok =
        Storage.call(config, :insert_code, [
          %{
            code_hash: Util.hash(code),
            client_id: request.client.client_id,
            client_name: request.client.client_name,
            redirect_uri: request.redirect_uri,
            code_challenge: request.code_challenge,
            dpop_jkt: request.dpop_jkt,
            resource: request.resource.id,
            scopes: granted,
            subject: to_string(subject),
            owner: opts[:owner] && to_string(opts[:owner]),
            claims: Keyword.get(opts, :claims, %{}),
            expires_at: Util.in_seconds(config.code_ttl)
          }
        ])

      {:ok, callback_url(config, request, code: code)}
    end
  end

  @doc "The user denied `request`. Returns the redirect back to the client with `access_denied`."
  @spec deny(Config.t(), request()) :: String.t()
  def deny(%Config{} = config, request), do: callback_url(config, request, error: "access_denied")

  # The redirect back carries `iss` (RFC 9207), including on errors.
  defp callback_url(config, request, fields) do
    query =
      fields
      |> Keyword.merge(state: request.state, iss: config.issuer)
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)
      |> URI.encode_query()

    uri = URI.parse(request.redirect_uri)
    URI.to_string(%{uri | query: Enum.join(Enum.reject([uri.query, query], &is_nil/1), "&")})
  end

  defp string(value) when is_binary(value), do: value
  defp string(_), do: nil
end
