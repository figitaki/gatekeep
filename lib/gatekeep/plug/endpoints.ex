defmodule Gatekeep.Plug.Endpoints do
  @moduledoc """
  Serves the issuer's JSON endpoints and discovery documents:

    * `POST <token>` - `Gatekeep.TokenEndpoint.token/3`
    * `POST <revoke>` - `Gatekeep.TokenEndpoint.revoke/3`
    * `POST <register>` - `Gatekeep.Registration.register/2`
    * `GET <jwks>` - the signer's public keys, with JWT access tokens
    * `GET /.well-known/oauth-authorization-server` - RFC 8414 metadata, also
      at the path-suffixed form of an issuer with a path
    * `GET /.well-known/oauth-protected-resource<path>` - RFC 9728 metadata of
      each enabled resource

  Other requests pass through untouched, so plug it in your endpoint before
  the router, or `forward` to it:

      plug Gatekeep.Plug.Endpoints, gatekeep: MyApp.Auth

  It parses its own form and JSON bodies, so it must run before
  `Plug.Parsers` or on routes that don't parse bodies. Responses carry
  `Cache-Control: no-store`, and CORS headers that let browser-based MCP
  clients call them; no cookies are read here.

  Never log the bodies of these requests: they hold codes, tokens, and
  assertions.
  """

  @behaviour Plug

  import Plug.Conn

  alias Gatekeep.{Config, Metadata, Registration, Resource, TokenEndpoint}

  @impl true
  def init(opts), do: Keyword.fetch!(opts, :gatekeep)

  @impl true
  def call(conn, gatekeep) do
    config = gatekeep.config()
    route(conn, config, conn.method, conn.request_path)
  end

  defp route(conn, config, method, path) do
    paths = endpoint_paths(config)

    cond do
      method == "OPTIONS" and handled?(config, path) ->
        preflight(conn)

      method == "POST" and path == paths[:token] ->
        token(conn, config)

      method == "POST" and path == paths[:revoke] ->
        revoke(conn, config)

      method == "POST" and path == paths[:register] ->
        register(conn, config)

      method == "GET" and path == paths[:jwks] and config.access_token_format == :jwt ->
        json(conn, 200, Metadata.jwks(config), :public)

      method == "GET" and path in as_metadata_paths(config) ->
        json(conn, 200, Metadata.authorization_server(config), :public)

      method == "GET" ->
        resource_metadata(conn, config, resource_at(config, path))

      true ->
        conn
    end
  end

  defp resource_metadata(conn, _config, nil), do: conn

  defp resource_metadata(conn, config, resource),
    do: json(conn, 200, Metadata.protected_resource(config, resource), :public)

  defp handled?(config, path) do
    path in Keyword.values(endpoint_paths(config)) or path in as_metadata_paths(config) or
      not is_nil(resource_at(config, path))
  end

  # The paths the endpoints are advertised at: `Config.endpoint/2` puts them
  # under the issuer, so an issuer with a path serves them under that path.
  defp endpoint_paths(config) do
    prefix = String.trim_trailing(URI.parse(config.issuer).path || "", "/")
    Enum.map(config.paths, fn {name, path} -> {name, prefix <> path} end)
  end

  # RFC 8414 §3.1: the well-known prefix, with the issuer's path appended.
  defp as_metadata_paths(config) do
    suffix = URI.parse(config.issuer).path || ""

    Enum.uniq([
      "/.well-known/oauth-authorization-server" <> String.trim_trailing(suffix, "/"),
      "/.well-known/oauth-authorization-server"
    ])
  end

  defp resource_at(config, path) do
    Enum.find(Config.enabled_resources(config), &(Resource.metadata_path(&1) == path))
  end

  defp token(conn, config) do
    with {:ok, params, conn} <- form_params(conn) do
      case TokenEndpoint.token(config, params, http(conn)) do
        {:ok, body} -> json(conn, 200, body)
        {:error, :invalid_client} -> oauth_error(conn, 401, :invalid_client)
        {:error, error} -> oauth_error(conn, 400, error)
      end
    end
  end

  defp revoke(conn, config) do
    with {:ok, params, conn} <- form_params(conn) do
      case TokenEndpoint.revoke(config, params, http(conn)) do
        :ok -> conn |> no_store() |> cors() |> send_resp(200, "") |> halt()
        {:error, :invalid_client} -> oauth_error(conn, 401, :invalid_client)
      end
    end
  end

  defp register(conn, config) do
    case Config.public_clients?(config) && read_body(conn, length: 64_000) do
      false ->
        conn

      {:ok, body, conn} ->
        params =
          case JSON.decode(body) do
            {:ok, params} -> params
            _ -> nil
          end

        register(conn, config, params)

      {:more, _partial, conn} ->
        json(conn, 413, %{error: "invalid_client_metadata", error_description: "body too large"})

      {:error, _reason} ->
        oauth_error(conn, 400, :invalid_request)
    end
  end

  defp register(conn, config, params) do
    case Registration.register(config, params) do
      {:ok, body} ->
        json(conn, 201, body)

      {:error, :not_found} ->
        conn

      {:error, error, description} ->
        json(conn, 400, %{error: error, error_description: description})
    end
  end

  defp http(conn) do
    %{
      authorization: conn |> get_req_header("authorization") |> List.first(),
      dpop: get_req_header(conn, "dpop")
    }
  end

  # The token and revocation endpoints take form bodies (RFC 6749 §3.2).
  # A parameter given twice is an error (§3.1), never a silent choice.
  defp form_params(conn) do
    with ["application/x-www-form-urlencoded" <> _] <- get_req_header(conn, "content-type"),
         {:ok, body, conn} <- read_body(conn, length: 64_000),
         pairs = URI.query_decoder(body) |> Enum.to_list(),
         keys = Enum.map(pairs, &elem(&1, 0)),
         true <- keys == Enum.uniq(keys) do
      {:ok, Map.new(pairs), conn}
    else
      _ -> oauth_error(conn, 400, :invalid_request)
    end
  rescue
    _ -> oauth_error(conn, 400, :invalid_request)
  end

  defp preflight(conn) do
    conn
    |> cors()
    |> put_resp_header("access-control-allow-methods", "GET, POST, OPTIONS")
    |> put_resp_header(
      "access-control-allow-headers",
      "authorization, content-type, dpop, mcp-protocol-version"
    )
    |> put_resp_header("access-control-max-age", "600")
    |> send_resp(204, "")
    |> halt()
  end

  defp oauth_error(conn, status, error), do: json(conn, status, %{error: to_string(error)})

  defp json(conn, status, body, cache \\ :no_store) do
    conn
    |> then(
      &if(cache == :public,
        do: put_resp_header(&1, "cache-control", "public, max-age=300"),
        else: no_store(&1)
      )
    )
    |> cors()
    |> put_resp_content_type("application/json")
    |> send_resp(status, JSON.encode!(body))
    |> halt()
  end

  defp no_store(conn) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("pragma", "no-cache")
  end

  defp cors(conn), do: put_resp_header(conn, "access-control-allow-origin", "*")
end
