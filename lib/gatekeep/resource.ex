defmodule Gatekeep.Resource do
  @moduledoc """
  A protected resource: an API, such as an MCP server, that accepts the
  issuer's access tokens. It has its own identifier (RFC 8707), which is the
  audience of its tokens, its own scopes, and its own protected resource
  metadata (RFC 9728).

  Resources are configured under `:resources`; see `Gatekeep.Config`. A token
  issued for one resource is refused by every other.
  """

  defstruct [
    :id,
    :scope_names,
    :scope_descriptions,
    :default_scopes,
    :client_auth_methods,
    :rotate_refresh_tokens,
    :dpop,
    :enabled,
    :name,
    :metadata
  ]

  @type t :: %__MODULE__{
          id: String.t(),
          scope_names: [String.t()],
          scope_descriptions: %{String.t() => String.t()},
          default_scopes: [String.t()],
          client_auth_methods: [String.t()],
          rotate_refresh_tokens: boolean(),
          dpop: :optional | :required,
          enabled: boolean(),
          name: String.t() | nil,
          metadata: map()
        }

  @doc false
  def new(opts) do
    {names, descriptions} =
      Enum.map_reduce(opts[:scopes], %{}, fn
        {name, description}, acc -> {name, Map.put(acc, name, description)}
        name, acc -> {name, Map.put(acc, name, name)}
      end)

    if Gatekeep.Util.canonical_url(opts[:id]) == :invalid do
      raise ArgumentError, "invalid Gatekeep config: resource #{inspect(opts[:id])} is not a URL"
    end

    default_scopes = opts[:default_scopes] || names

    if default_scopes -- names != [] do
      raise ArgumentError,
            "invalid Gatekeep config: resource #{inspect(opts[:id])} has default scopes " <>
              "it does not offer: #{inspect(default_scopes -- names)}"
    end

    %__MODULE__{
      id: opts[:id],
      scope_names: names,
      scope_descriptions: descriptions,
      default_scopes: default_scopes,
      client_auth_methods: opts[:client_auth_methods],
      rotate_refresh_tokens: opts[:rotate_refresh_tokens],
      dpop: opts[:dpop],
      enabled: opts[:enabled],
      name: opts[:name],
      metadata: opts[:metadata]
    }
  end

  @doc """
  Parses a requested scope string. A missing or empty scope gets the
  resource's default scopes. Returns `:error` when any scope is not one the
  resource offers.
  """
  @spec parse_scopes(t(), String.t() | nil) :: {:ok, [String.t()]} | :error
  def parse_scopes(%__MODULE__{} = resource, scope) do
    case Gatekeep.Util.split_scope(scope) do
      [] ->
        {:ok, resource.default_scopes}

      scopes ->
        if Enum.all?(scopes, &(&1 in resource.scope_names)),
          do: {:ok, Enum.filter(resource.scope_names, &(&1 in scopes))},
          else: :error
    end
  end

  @doc """
  The path of the resource's metadata: the well-known prefix with the
  resource's path appended (RFC 9728 §3.1), such as
  `/.well-known/oauth-protected-resource/mcp` for `https://example.com/mcp`.
  """
  @spec metadata_path(t()) :: String.t()
  def metadata_path(%__MODULE__{id: id}) do
    "/.well-known/oauth-protected-resource" <> String.trim_trailing(URI.parse(id).path || "", "/")
  end

  @doc "The URL of the resource's metadata, for the `resource_metadata` challenge parameter."
  @spec metadata_url(t()) :: String.t()
  def metadata_url(%__MODULE__{id: id} = resource) do
    uri = URI.parse(id)

    URI.to_string(%URI{
      scheme: uri.scheme,
      host: uri.host,
      port: uri.port,
      path: metadata_path(resource)
    })
  end

  @doc """
  The public URL of `path` on the resource's origin. DPoP proofs are checked
  against it, never against the Host header the server received.
  """
  @spec url_for(t(), String.t()) :: String.t()
  def url_for(%__MODULE__{id: id}, path) do
    uri = URI.parse(id)
    URI.to_string(%URI{scheme: uri.scheme, host: uri.host, port: uri.port, path: path})
  end
end
