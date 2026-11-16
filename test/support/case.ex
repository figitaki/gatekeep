defmodule Gatekeep.Case do
  @moduledoc """
  The case of tests that use the database and the test issuer. Each test gets
  a fresh sandbox, a fresh client cache, and the base config; pass
  `config: [...]` with `@tag` to override keys.
  """
  use ExUnit.CaseTemplate

  import Plug.Test
  import Plug.Conn

  alias Gatekeep.{TestAuth, TestClient}

  using do
    quote do
      import Gatekeep.Case
      alias Gatekeep.{TestAuth, TestClient}
    end
  end

  setup tags do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Gatekeep.TestRepo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
    TestAuth.put_config(Map.get(tags, :config, []))
    :ets.delete_all_objects(Gatekeep.Cache.table(TestAuth))
    :ok
  end

  @doc "Sends `conn` through the test router."
  def call(conn), do: Gatekeep.TestRouter.call(conn, Gatekeep.TestRouter.init([]))

  @doc "POSTs a form to the issuer."
  def post_form(path, params, headers \\ []) do
    conn(:post, path, URI.encode_query(params))
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> put_headers(headers)
    |> call()
  end

  def get_path(path, headers \\ []), do: conn(:get, path) |> put_headers(headers) |> call()

  defp put_headers(conn, headers),
    do: Enum.reduce(headers, conn, fn {k, v}, conn -> put_req_header(conn, k, v) end)

  def json_body(conn), do: JSON.decode!(conn.resp_body)

  @doc "Authorization params for `client` with a fresh PKCE pair. Returns `{params, verifier}`."
  def authorize_params(client, extra \\ %{}) do
    {verifier, challenge} = TestClient.pkce()

    params =
      Map.merge(
        %{
          "response_type" => "code",
          "client_id" => client.client_id,
          "redirect_uri" => client.redirect_uri,
          "code_challenge" => challenge,
          "code_challenge_method" => "S256",
          "state" => "xyz",
          "resource" => TestAuth.mcp()
        },
        extra
      )

    {params, verifier}
  end

  @doc """
  Runs authorization for `client` through the plug and approves as
  `subject`. Returns `{code, verifier, params}`.
  """
  def authorize(client, extra \\ %{}, approve_opts \\ [subject: "user:1"]) do
    {params, verifier} = authorize_params(client, extra)
    conn = get_path("/oauth/authorize?" <> URI.encode_query(params))
    200 = conn.status
    assert_received {:consent, request}
    {:ok, url} = Gatekeep.Authorization.approve(TestAuth.config(), request, approve_opts)
    query = URI.decode_query(URI.parse(url).query)
    {query["code"], verifier, params}
  end

  @doc "Exchanges `code` at the token endpoint."
  def exchange(client, code, verifier, extra \\ %{}, headers \\ []) do
    post_form(
      "/oauth/token",
      Map.merge(
        TestClient.client_auth(client)
        |> Map.merge(%{
          "grant_type" => "authorization_code",
          "code" => code,
          "code_verifier" => verifier,
          "redirect_uri" => client.redirect_uri
        }),
        extra
      ),
      headers
    )
  end

  @doc "Authorization and code exchange in one: the token response."
  def sign_in(client, extra \\ %{}, approve_opts \\ [subject: "user:1"]) do
    {code, verifier, _} = authorize(client, extra, approve_opts)
    conn = exchange(client, code, verifier)
    200 = conn.status
    json_body(conn)
  end

  def refresh(client, refresh_token, extra \\ %{}, headers \\ []) do
    post_form(
      "/oauth/token",
      TestClient.client_auth(client)
      |> Map.merge(%{"grant_type" => "refresh_token", "refresh_token" => refresh_token})
      |> Map.merge(extra),
      headers
    )
  end

  def bearer(token), do: [{"authorization", "Bearer " <> token}]
end
