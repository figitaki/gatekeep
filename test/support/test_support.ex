defmodule Gatekeep.TestRepo do
  @moduledoc false
  use Ecto.Repo, otp_app: :gatekeep, adapter: Ecto.Adapters.Postgres
end

defmodule Gatekeep.TestAuth do
  @moduledoc false
  use Gatekeep, otp_app: :gatekeep

  @issuer "https://auth.test"
  def issuer, do: @issuer
  def mcp, do: "https://mcp.test/mcp"
  def other, do: "https://api.test/other"

  @doc "The base config of the tests. `overrides` replace its keys."
  def base_config(overrides \\ []) do
    Keyword.merge(
      [
        issuer: @issuer,
        storage: {Gatekeep.Storage.Ecto, repo: Gatekeep.TestRepo},
        consent: Gatekeep.TestConsent,
        fetcher: Gatekeep.TestFetcher,
        default_resource: mcp(),
        resources: [
          [
            id: mcp(),
            name: "Test MCP",
            scopes: [{"notes:read", "Read notes"}, {"notes:write", "Write notes"}]
          ],
          [id: other(), scopes: ["other:read"], rotate_refresh_tokens: false]
        ]
      ],
      overrides
    )
  end

  def put_config(overrides \\ []),
    do: Application.put_env(:gatekeep, __MODULE__, base_config(overrides))
end

defmodule Gatekeep.TestConsent do
  @moduledoc false
  @behaviour Gatekeep.Consent
  import Plug.Conn

  @impl true
  def handle_authorization(conn, request) do
    send(self(), {:consent, request})
    send_resp(conn, 200, "consent for " <> Gatekeep.Client.label(request.client))
  end
end

defmodule Gatekeep.TestFetcher do
  @moduledoc false
  @behaviour Gatekeep.Fetcher
  @table :gatekeep_test_fetcher

  def setup do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    :ok
  end

  def put(url, body), do: :ets.insert(@table, {url, body})

  def count(url) do
    case :ets.lookup(@table, {:count, url}) do
      [{_, n}] -> n
      [] -> 0
    end
  end

  @impl true
  def get(url, _config) do
    :ets.update_counter(@table, {:count, url}, 1, {{:count, url}, 0})

    case :ets.lookup(@table, url) do
      [{^url, body}] -> {:ok, %{status: 200, body: JSON.encode!(body)}}
      [] -> {:ok, %{status: 404, body: ""}}
    end
  end
end

defmodule Gatekeep.TestRouter do
  @moduledoc false
  use Plug.Router

  alias Gatekeep.Plug.Resource

  plug Gatekeep.Plug.Endpoints, gatekeep: Gatekeep.TestAuth
  plug :fetch_query_params
  plug :match
  plug :dispatch

  get "/oauth/authorize", to: Gatekeep.Plug.Authorize, init_opts: [gatekeep: Gatekeep.TestAuth]

  get "/mcp" do
    conn
    |> Resource.call(
      Resource.init(
        gatekeep: Gatekeep.TestAuth,
        resource: Gatekeep.TestAuth.mcp(),
        scopes: List.wrap(conn.query_params["need"])
      )
    )
    |> then(fn
      %{halted: true} = conn -> conn
      conn -> send_resp(conn, 200, "hello " <> conn.assigns.gatekeep_token.subject)
    end)
  end

  get "/other" do
    conn
    |> Resource.call(
      Resource.init(gatekeep: Gatekeep.TestAuth, resource: Gatekeep.TestAuth.other())
    )
    |> then(fn
      %{halted: true} = conn -> conn
      conn -> send_resp(conn, 200, "other")
    end)
  end

  match _, do: send_resp(conn, 404, "not found")
end

defmodule Gatekeep.TestClient do
  @moduledoc """
  An OAuth client for tests: an ES256 key and an RSA key in its key set,
  its client ID metadata document served by `Gatekeep.TestFetcher`, and
  signers for client assertions and DPoP proofs.
  """

  alias Gatekeep.JOSE

  defstruct [:client_id, :jwks_uri, :redirect_uri, :root, :rsa]

  @doc """
  A new client with unique URLs. `:metadata` adds or replaces fields of its
  document; `public: true` publishes no keys.
  """
  def new(opts \\ []) do
    n = System.unique_integer([:positive])
    base = "https://client#{n}.example"

    client = %__MODULE__{
      client_id: "#{base}/client.json",
      jwks_uri: "#{base}/jwks.json",
      redirect_uri: "#{base}/callback",
      root: ec_key("root-#{n}"),
      rsa: rsa_key("rsa-#{n}")
    }

    metadata =
      if Keyword.get(opts, :public),
        do: %{"jwks_uri" => nil, "token_endpoint_auth_method" => "none"},
        else: %{}

    publish(client, Map.merge(metadata, Keyword.get(opts, :metadata, %{})))
  end

  def publish(client, extra \\ %{}, keys \\ nil) do
    Gatekeep.TestFetcher.setup()

    metadata =
      %{
        "client_id" => client.client_id,
        "client_name" => "Test Client",
        "jwks_uri" => client.jwks_uri,
        "redirect_uris" => [client.redirect_uri, "http://127.0.0.1/callback"],
        "token_endpoint_auth_method" => "private_key_jwt"
      }
      |> Map.merge(extra)
      |> Map.reject(fn {_k, v} -> is_nil(v) end)

    Gatekeep.TestFetcher.put(client.client_id, metadata)

    Gatekeep.TestFetcher.put(client.jwks_uri, %{
      "keys" => keys || [client.root.public, client.rsa.public]
    })

    client
  end

  def client_assertion(client, opts \\ []) do
    iat = Keyword.get(opts, :iat, now())

    signer =
      Keyword.get(opts, :key) || if(Keyword.get(opts, :rsa), do: client.rsa, else: client.root)

    JOSE.sign(
      %{"typ" => "JWT", "kid" => signer.kid},
      %{
        "iss" => Keyword.get(opts, :iss, client.client_id),
        "sub" => Keyword.get(opts, :sub, client.client_id),
        "aud" => Keyword.get(opts, :aud, Gatekeep.TestAuth.issuer()),
        "iat" => iat,
        "exp" => Keyword.get(opts, :exp, iat + 120),
        "jti" => Keyword.get(opts, :jti, random_id())
      }
      |> then(&if(nbf = opts[:nbf], do: Map.put(&1, "nbf", nbf), else: &1)),
      signer
    )
  end

  @doc "Form params that authenticate the client with private_key_jwt."
  def client_auth(client, opts \\ []) do
    %{
      "client_id" => client.client_id,
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion" => client_assertion(client, opts)
    }
  end

  @doc "A DPoP proof with `key` (an `ec_key/1`)."
  def dpop_proof(key, method, url, opts \\ []) do
    claims =
      %{
        "jti" => Keyword.get(opts, :jti, random_id()),
        "htm" => method,
        "htu" => url,
        "iat" => Keyword.get(opts, :iat, now())
      }
      |> then(fn c ->
        case Keyword.get(opts, :access_token) do
          nil -> c
          token -> Map.put(c, "ath", JOSE.digest(token))
        end
      end)

    JOSE.sign(
      %{
        "typ" => Keyword.get(opts, :typ, "dpop+jwt"),
        "jwk" => Map.drop(key.public, ["kid", "alg"])
      },
      claims,
      key
    )
  end

  def jkt(key), do: key.public |> Map.drop(["kid", "alg"]) |> JOSE.thumbprint() |> elem(1)

  def ec_key(kid) do
    {<<4, x::binary-size(32), y::binary-size(32)>>, d} = :crypto.generate_key(:ecdh, :secp256r1)

    public =
      %{"kty" => "EC", "crv" => "P-256", "x" => b64(x), "y" => b64(y)}
      |> then(&if(kid, do: Map.merge(&1, %{"kid" => kid, "alg" => "ES256"}), else: &1))

    %{alg: "ES256", kid: kid, public: public, private: d}
  end

  def rsa_key(kid, alg \\ "RS256") do
    {[e, n], private} = :persistent_term.get({__MODULE__, :rsa}, nil) || generate_rsa()

    %{
      alg: alg,
      kid: kid,
      public: %{"kty" => "RSA", "e" => b64(e), "n" => b64(n), "kid" => kid, "alg" => alg},
      private: private
    }
  end

  defp generate_rsa do
    key = :crypto.generate_key(:rsa, {2048, 65_537})
    :persistent_term.put({__MODULE__, :rsa}, key)
    key
  end

  def pkce do
    verifier = random_id() <> random_id()
    {verifier, JOSE.digest(verifier)}
  end

  def random_id, do: :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  def now, do: System.system_time(:second)
  defp b64(bin), do: Base.url_encode64(bin, padding: false)
end
