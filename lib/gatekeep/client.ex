defmodule Gatekeep.Client do
  @moduledoc """
  An OAuth client, as `Gatekeep.Clients.fetch/2` describes it, whatever its
  source:

    * `:metadata_document` - an HTTPS `client_id` naming its client ID
      metadata document (CIMD), as Claude and ChatGPT publish.
    * `:registered` - registered through dynamic client registration
      (RFC 7591). Always public, and its name is not verified.
    * `:static` - pre-registered in config under `:clients`, such as a
      confidential server-side client.

  `auth_methods` lists the token endpoint authentication methods the client
  may use. `dpop_bound` is true when its metadata declares
  `dpop_bound_access_tokens` (RFC 9449 §5.2), which makes DPoP proofs
  mandatory for it.
  """

  defstruct [
    :client_id,
    :client_name,
    :kind,
    :jwks_uri,
    :secret_hash,
    :scopes,
    redirect_uris: [],
    auth_methods: [],
    grant_types: [],
    keys: [],
    dpop_bound: false
  ]

  @type t :: %__MODULE__{
          client_id: String.t(),
          client_name: String.t() | nil,
          kind: :metadata_document | :registered | :static,
          jwks_uri: String.t() | nil,
          secret_hash: String.t() | nil,
          scopes: [String.t()] | nil,
          redirect_uris: [String.t()],
          auth_methods: [String.t()],
          grant_types: [String.t()],
          keys: [map()],
          dpop_bound: boolean()
        }

  @doc false
  def from_static(opts) do
    keys = opts[:jwks] || []
    keyed? = keys != []

    methods =
      Enum.concat([
        if(opts[:public], do: ["none"], else: []),
        if(keyed?, do: ["private_key_jwt"], else: []),
        if(opts[:client_secret_sha256],
          do: ["client_secret_basic", "client_secret_post"],
          else: []
        )
      ])

    if methods == [] do
      raise ArgumentError,
            "invalid Gatekeep config: client #{inspect(opts[:client_id])} needs :jwks, " <>
              ":client_secret_sha256, or public: true"
    end

    %__MODULE__{
      client_id: opts[:client_id],
      client_name: opts[:client_name],
      kind: :static,
      redirect_uris: opts[:redirect_uris],
      keys: Enum.filter(keys, &Gatekeep.JOSE.public_key?/1),
      secret_hash: opts[:client_secret_sha256] && String.downcase(opts[:client_secret_sha256]),
      auth_methods: methods,
      grant_types: opts[:grant_types],
      scopes: opts[:scopes],
      dpop_bound: opts[:dpop_bound_access_tokens]
    }
  end

  @doc "Whether the client may use `grant_type`."
  @spec grant_allowed?(t(), String.t()) :: boolean()
  def grant_allowed?(%__MODULE__{} = client, grant_type), do: grant_type in client.grant_types

  @doc """
  A label for consent pages: the verified host of a metadata document client,
  or the name of another client.
  """
  @spec label(t()) :: String.t()
  def label(%__MODULE__{kind: :metadata_document, client_id: client_id}),
    do: URI.parse(client_id).host

  def label(%__MODULE__{client_name: name, client_id: id}), do: name || id
end
