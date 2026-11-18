defmodule Gatekeep.Config do
  @resource_schema [
    id: [
      type: :string,
      required: true,
      doc:
        "The resource identifier (RFC 8707), such as `\"https://example.com/mcp\"`. It is the " <>
          "audience of the resource's tokens and the `resource` of its protected resource metadata."
    ],
    scopes: [
      type: {:list, {:or, [:string, {:tuple, [:string, :string]}]}},
      default: [],
      doc:
        "The scopes the resource offers, in display order: names, or `{name, description}` " <>
          "tuples for the consent page."
    ],
    default_scopes: [
      type: {:or, [{:list, :string}, nil]},
      default: nil,
      doc: "Scopes granted to a request without `scope`. Defaults to every scope."
    ],
    client_auth_methods: [
      type:
        {:list, {:in, ["none", "private_key_jwt", "client_secret_basic", "client_secret_post"]}},
      default: ["none", "private_key_jwt", "client_secret_basic", "client_secret_post"],
      doc:
        "Token endpoint authentication methods a client may use to get this resource's " <>
          "tokens. `\"none\"` admits public clients, which rely on PKCE, and turns on dynamic " <>
          "client registration."
    ],
    rotate_refresh_tokens: [
      type: :boolean,
      default: true,
      doc: "Rotate refresh tokens on every use. Presenting a replaced one then revokes the grant."
    ],
    dpop: [
      type: {:in, [:optional, :required]},
      default: :optional,
      doc:
        "`:optional` binds tokens to a DPoP key when the token request carries a proof. " <>
          "`:required` issues no Bearer tokens for this resource."
    ],
    allowed_clients: [
      type: {:or, [{:list, :string}, nil]},
      default: nil,
      doc:
        "The only client IDs that may get this resource's tokens, or nil for any client, such " <>
          "as an app's own command-line tool. A resource that lists its clients doesn't turn " <>
          "on dynamic client registration."
    ],
    enabled: [type: :boolean, default: true, doc: "Whether tokens are issued for the resource."],
    name: [type: {:or, [:string, nil]}, default: nil, doc: "`resource_name` in its metadata."],
    metadata: [
      type: {:map, :string, :any},
      default: %{},
      doc: "More fields for its protected resource metadata (RFC 9728 §2)."
    ]
  ]

  @client_schema [
    client_id: [type: :string, required: true, doc: "The client's ID."],
    client_name: [type: {:or, [:string, nil]}, default: nil, doc: "Its display name."],
    redirect_uris: [
      type: {:list, :string},
      default: [],
      doc: "Redirect URIs for the authorization code grant."
    ],
    jwks: [
      type: {:or, [{:list, {:map, :string, :any}}, nil]},
      default: nil,
      doc: "Public keys for `private_key_jwt`, as JWK maps."
    ],
    client_secret_sha256: [
      type: {:or, [:string, nil]},
      default: nil,
      doc:
        "The hex SHA-256 of its client secret (`Gatekeep.hash_client_secret/1`), for " <>
          "`client_secret_basic` and `client_secret_post`."
    ],
    public: [
      type: :boolean,
      default: false,
      doc: "Allow the client to authenticate with `\"none\"`, relying on PKCE."
    ],
    grant_types: [
      type: {:list, :string},
      default: ["authorization_code", "refresh_token"],
      doc:
        ~s(Grants the client may use, such as `"authorization_code"`, `"refresh_token"`, ) <>
          ~s(`"client_credentials"`, `"urn:ietf:params:oauth:grant-type:device_code"`, and ) <>
          ~s(`"urn:ietf:params:oauth:grant-type:jwt-bearer"`.)
    ],
    scopes: [
      type: {:or, [{:list, :string}, nil]},
      default: nil,
      doc: "The only scopes the client may get, or nil for any."
    ],
    subject: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "The subject of its client credentials tokens. Defaults to the client ID."
    ],
    dpop_bound_access_tokens: [
      type: :boolean,
      default: false,
      doc: "Refuse token requests from this client that carry no DPoP proof (RFC 9449 §5.2)."
    ]
  ]

  @enterprise_schema [
    module: [
      type: :atom,
      required: true,
      doc: "A `Gatekeep.Enterprise` module that trusts issuers and resolves users."
    ],
    max_assertion_lifetime: [
      type: :pos_integer,
      default: 600,
      doc: "The longest `exp - iat` an identity assertion may have, in seconds."
    ],
    require_resource_claim: [
      type: :boolean,
      default: false,
      doc: "Refuse identity assertions without a `resource` claim."
    ]
  ]

  @schema [
    name: [type: :atom, required: true, doc: "The issuer module. `use Gatekeep` sets it."],
    issuer: [
      type: :string,
      required: true,
      doc:
        "The issuer identifier (RFC 8414): an HTTPS URL, such as `\"https://example.com\"`. " <>
          "It is the `iss` of authorization responses and the audience of client assertions."
    ],
    storage: [
      type: {:tuple, [:atom, :keyword_list]},
      required: true,
      doc:
        "A `Gatekeep.Storage` module and its options, such as `{Gatekeep.Storage.Ecto, repo: MyApp.Repo}`."
    ],
    resources: [
      type: {:list, {:keyword_list, @resource_schema}},
      required: true,
      doc:
        "The protected resources. Each takes these options:\n\n" <>
          NimbleOptions.docs(@resource_schema, nest_level: 1)
    ],
    default_resource: [
      type: {:or, [:string, nil]},
      default: nil,
      doc:
        "The resource of an authorization request that names no `resource` and no scope " <>
          "of another resource."
    ],
    clients: [
      type: {:list, {:keyword_list, @client_schema}},
      default: [],
      doc:
        "Pre-registered clients, such as machine clients for the client credentials grant. " <>
          "Each takes these options:\n\n" <> NimbleOptions.docs(@client_schema, nest_level: 1)
    ],
    registered_client_prefix: [
      type: {:custom, __MODULE__, :validate_client_prefix, []},
      default: "gkc_",
      doc:
        "The prefix of client IDs issued by dynamic client registration: letters and digits " <>
          "ending in `_`, such as `\"gkc_\"`. Set it to keep the IDs an earlier issuer handed out."
    ],
    consent: [
      type: :atom,
      default: nil,
      doc: "The `Gatekeep.Consent` module `Gatekeep.Plug.Authorize` hands requests to."
    ],
    enterprise: [
      type: {:or, [{:keyword_list, @enterprise_schema}, nil]},
      default: nil,
      doc:
        "Turns on enterprise-managed authorization (identity assertion grants). Takes:\n\n" <>
          NimbleOptions.docs(@enterprise_schema, nest_level: 1)
    ],
    signer: [
      type: {:or, [{:tuple, [:atom, :keyword_list]}, nil]},
      default: nil,
      doc: "A `Gatekeep.Signer` and its options. Needed for `access_token_format: :jwt`."
    ],
    access_token_format: [
      type: {:in, [:opaque, :jwt]},
      default: :opaque,
      doc:
        "`:opaque` random tokens, or `:jwt` tokens (RFC 9068) signed by `:signer` that other " <>
          "servers can verify with the keys at the JWKS endpoint. Gatekeep still checks " <>
          "revocation for both."
    ],
    paths: [
      type: :keyword_list,
      default: [],
      doc:
        "Endpoint paths under the issuer: `:authorize` (`/oauth/authorize`), `:token`, " <>
          "`:revoke`, `:register`, `:jwks` (`/oauth/<name>`), and `:device_authorization` " <>
          "(`/oauth/device_authorization`)."
    ],
    device_verification_uri: [
      type: {:custom, __MODULE__, :validate_verification_uri, []},
      default: nil,
      doc:
        "The page where people enter a device's user code (RFC 8628 §3.2), as a path under " <>
          "the issuer, such as `\"/device\"`, or an absolute URL. Setting it turns on the " <>
          "device authorization grant; see `Gatekeep.DeviceAuthorization`."
    ],
    device_code_ttl: [
      type: :pos_integer,
      default: 600,
      doc: "How long a device code and its user code wait for approval, seconds."
    ],
    device_poll_interval: [
      type: :pos_integer,
      default: 5,
      doc:
        "The seconds a device waits between token requests. Polling faster gets `slow_down` " <>
          "and 5 more seconds (RFC 8628 §3.5)."
    ],
    code_ttl: [type: :pos_integer, default: 120, doc: "Authorization code lifetime, seconds."],
    access_token_ttl: [type: :pos_integer, default: 3600, doc: "Access token lifetime, seconds."],
    refresh_token_ttl: [
      type: :pos_integer,
      default: 90 * 24 * 3600,
      doc: "How long a grant's refresh token works after the grant is created, seconds."
    ],
    clock_skew: [type: :non_neg_integer, default: 30, doc: "Allowed clock skew, seconds."],
    dpop_proof_window: [
      type: :pos_integer,
      default: 60,
      doc: "How old a DPoP proof's `iat` may be, seconds, before the clock skew."
    ],
    dpop_signing_algs: [
      type: {:list, {:in, ["ES256", "PS384", "RS256"]}},
      default: ["ES256", "PS384", "RS256"],
      doc: "Algorithms accepted for DPoP proofs."
    ],
    client_assertion_algs: [
      type: {:list, {:in, ["ES256", "PS384", "RS256"]}},
      default: ["ES256", "PS384", "RS256"],
      doc: "Algorithms accepted for `private_key_jwt` client assertions."
    ],
    token_endpoint_audience_clients: [
      type: {:list, :string},
      default: [],
      doc:
        "Clients whose assertions may name the token endpoint as `aud`, instead of only the " <>
          "issuer (RFC 7523bis)."
    ],
    blocked_clients: [
      type: {:list, :string},
      default: [],
      doc: "Client IDs refused everywhere. Their tokens stop working at once."
    ],
    client_cache_seconds: [
      type: :pos_integer,
      default: 300,
      doc: "How long fetched client metadata and keys are cached."
    ],
    client_cache_size: [
      type: :pos_integer,
      default: 10_000,
      doc: "The most entries the cache holds; past that, results are used but not cached."
    ],
    fetcher: [
      type: :atom,
      default: Gatekeep.Fetcher,
      doc: "The `Gatekeep.Fetcher` used for metadata documents and key sets."
    ],
    allow_private_hosts: [
      type: {:list, :string},
      default: [],
      doc: "Hosts the fetcher may reach on private addresses, for development."
    ]
  ]

  @moduledoc """
  Configuration of a Gatekeep issuer. `use Gatekeep` reads it from the
  application environment of the issuer module and validates it with
  `new!/1`.

  ## Options

  #{NimbleOptions.docs(@schema)}
  """

  alias Gatekeep.{Client, Resource}

  defstruct Keyword.keys(@schema)

  @type t :: %__MODULE__{}

  @default_paths [
    authorize: "/oauth/authorize",
    token: "/oauth/token",
    revoke: "/oauth/revoke",
    register: "/oauth/register",
    jwks: "/oauth/jwks",
    device_authorization: "/oauth/device_authorization"
  ]

  @doc false
  def validate_client_prefix(prefix) do
    if is_binary(prefix) and prefix =~ ~r/\A[A-Za-z0-9]+_\z/,
      do: {:ok, prefix},
      else: {:error, "expected letters and digits ending in \"_\", got: #{inspect(prefix)}"}
  end

  @doc false
  def validate_verification_uri(nil), do: {:ok, nil}
  def validate_verification_uri("/" <> _ = path), do: {:ok, path}

  def validate_verification_uri(uri) when is_binary(uri) do
    case URI.parse(uri) do
      %URI{scheme: scheme, host: host, fragment: nil}
      when scheme in ["https", "http"] and is_binary(host) and host != "" ->
        {:ok, uri}

      _ ->
        {:error, "expected a path or an HTTP(S) URL, got: #{inspect(uri)}"}
    end
  end

  def validate_verification_uri(uri),
    do: {:error, "expected a path or an HTTP(S) URL, got: #{inspect(uri)}"}

  @doc "Validates `opts` and builds the config. Raises `ArgumentError` on invalid options."
  @spec new!(keyword()) :: t()
  def new!(opts) do
    case NimbleOptions.validate(opts, @schema) do
      {:ok, opts} ->
        config = struct!(__MODULE__, opts)

        %{
          config
          | resources: Enum.map(config.resources, &Resource.new/1),
            clients: Enum.map(config.clients, &Client.from_static/1),
            paths: Keyword.merge(@default_paths, config.paths),
            issuer: String.trim_trailing(config.issuer, "/")
        }
        |> check!()

      {:error, error} ->
        raise ArgumentError, "invalid Gatekeep config: " <> Exception.message(error)
    end
  end

  defp check!(config) do
    if config.access_token_format == :jwt and is_nil(config.signer) do
      raise ArgumentError, "invalid Gatekeep config: access_token_format: :jwt needs a :signer"
    end

    if config.default_resource && is_nil(resource(config, config.default_resource)) do
      raise ArgumentError, "invalid Gatekeep config: :default_resource is not one of :resources"
    end

    config
  end

  @doc "The URL of the endpoint `name`, such as `:token`."
  @spec endpoint(t(), atom()) :: String.t()
  def endpoint(%__MODULE__{} = config, name),
    do: config.issuer <> Keyword.fetch!(config.paths, name)

  @doc "The resources that issue tokens now."
  @spec enabled_resources(t()) :: [Resource.t()]
  def enabled_resources(%__MODULE__{resources: resources}), do: Enum.filter(resources, & &1.enabled)

  @doc "The configured resource whose identifier matches `id`, enabled or not."
  @spec resource(t(), String.t() | nil) :: Resource.t() | nil
  def resource(%__MODULE__{resources: resources}, id) when is_binary(id),
    do: Enum.find(resources, &Gatekeep.Util.same_url?(id, &1.id))

  def resource(_config, _id), do: nil

  @doc """
  Whether an enabled resource takes any public client, which turns on
  registration. A resource that lists its `allowed_clients` doesn't count:
  a registered client could never be one of them.
  """
  @spec public_clients?(t()) :: boolean()
  def public_clients?(config) do
    Enum.any?(
      enabled_resources(config),
      &("none" in &1.client_auth_methods and is_nil(&1.allowed_clients))
    )
  end

  @doc """
  The page where people enter user codes, as an absolute URL, or nil when
  the device authorization grant is off.
  """
  @spec device_verification_uri(t()) :: String.t() | nil
  def device_verification_uri(%__MODULE__{device_verification_uri: nil}), do: nil

  def device_verification_uri(%__MODULE__{device_verification_uri: "/" <> _ = path} = config),
    do: config.issuer <> path

  def device_verification_uri(%__MODULE__{device_verification_uri: uri}), do: uri
end
