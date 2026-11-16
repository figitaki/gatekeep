defmodule Gatekeep.Plug.Resource do
  @moduledoc """
  Protects an API with the issuer's access tokens.

      plug Gatekeep.Plug.Resource,
        gatekeep: MyApp.Auth,
        resource: "https://example.com/mcp",
        scopes: ["notes:read"]

  On success it assigns the `Gatekeep.Token` as `conn.assigns.gatekeep_token`.
  Otherwise it halts with the challenges MCP clients follow (RFC 6750 §3,
  RFC 9728 §5.1, RFC 9449 §7.1), one per scheme the resource accepts:

    * no token: 401 with `resource_metadata` and `scope`, and no error code;
    * a bad, expired, revoked, or other resource's token, or a valid DPoP
      proof from a key the token isn't bound to: 401 `invalid_token`;
    * a DPoP proof that fails its checks: 401 `invalid_dpop_proof`;
    * a token without the scopes: 403 `insufficient_scope`, naming them.

  Options:

    * `:gatekeep` (required) - the issuer module.
    * `:resource` (required) - the resource identifier.
    * `:scopes` - scopes every request needs (default `[]`).
    * `:assign` - the assign name (default `:gatekeep_token`).
  """

  @behaviour Plug

  import Plug.Conn

  alias Gatekeep.{Config, Resource, Token}

  @impl true
  def init(opts) do
    %{
      gatekeep: Keyword.fetch!(opts, :gatekeep),
      resource: Keyword.fetch!(opts, :resource),
      scopes: Keyword.get(opts, :scopes, []),
      assign: Keyword.get(opts, :assign, :gatekeep_token)
    }
  end

  @impl true
  def call(conn, opts) do
    config = opts.gatekeep.config()

    resource =
      Config.resource(config, opts.resource) ||
        raise ArgumentError, "unknown Gatekeep resource #{inspect(opts.resource)}"

    scheme = scheme(conn)

    request = %{
      authorization: conn |> get_req_header("authorization") |> List.first(),
      dpop: get_req_header(conn, "dpop"),
      method: conn.method,
      path: conn.request_path
    }

    case Token.authenticate(config, resource, request) do
      {:ok, token} ->
        if Token.has_scopes?(token, opts.scopes) do
          assign(conn, opts.assign, token)
        else
          params = [error: "insufficient_scope", scope: Enum.join(opts.scopes, " ")]
          reject(conn, opts, 403, challenge(config, resource, scheme, params), "insufficient_scope")
        end

      {:error, :missing_token} ->
        params = if opts.scopes == [], do: [], else: [scope: Enum.join(opts.scopes, " ")]
        reject(conn, opts, 401, challenge(config, resource, nil, params), "unauthorized")

      {:error, error} ->
        reject(
          conn,
          opts,
          401,
          challenge(config, resource, scheme, error: to_string(error)),
          to_string(error)
        )
    end
  end

  defp scheme(conn) do
    case conn |> get_req_header("authorization") |> List.first() |> Token.credentials() do
      {:ok, scheme, _token} -> scheme
      _ -> nil
    end
  end

  @doc """
  The `WWW-Authenticate` value for `resource`: a `Bearer` challenge (unless
  the resource requires DPoP) and a `DPoP` challenge with its algorithms.
  Error parameters go in the challenge of the scheme the request used, or in
  both when it used none (RFC 9449 §7.1).
  """
  @spec challenge(Config.t(), Resource.t(), :bearer | :dpop | nil, keyword()) :: String.t()
  def challenge(config, resource, scheme, params) do
    base = [resource_metadata: Resource.metadata_url(resource)]
    bearer = base ++ if(scheme in [nil, :bearer], do: params, else: [])

    dpop =
      base ++
        if(scheme in [nil, :dpop], do: params, else: []) ++
        [algs: Enum.join(config.dpop_signing_algs, " ")]

    challenges = [auth_challenge("DPoP", dpop)]

    challenges =
      if resource.dpop == :required,
        do: challenges,
        else: [auth_challenge("Bearer", bearer) | challenges]

    Enum.join(challenges, ", ")
  end

  defp auth_challenge(name, params),
    do: name <> " " <> Enum.map_join(params, ", ", fn {key, value} -> ~s(#{key}="#{value}") end)

  defp reject(conn, _opts, status, challenge, error) do
    conn
    |> put_resp_header("www-authenticate", challenge)
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_content_type("application/json")
    |> send_resp(status, JSON.encode!(%{error: error}))
    |> halt()
  end
end
