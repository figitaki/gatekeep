defmodule Gatekeep.Plug.Authorize do
  @moduledoc """
  The authorization endpoint. Checks the request with
  `Gatekeep.Authorization.check/2`, then:

    * hands a valid request to the configured `Gatekeep.Consent` module's
      `c:Gatekeep.Consent.handle_authorization/2`;
    * redirects an invalid request back to the client with the error and
      `iss`, when that is safe;
    * otherwise calls `c:Gatekeep.Consent.handle_error/2`, or answers a
      plain-text 400.

  Mount it on the authorize path in a browser pipeline, so the consent
  module has the session and CSRF protection it needs:

      scope "/oauth" do
        pipe_through :browser
        get "/authorize", Gatekeep.Plug.Authorize, gatekeep: MyApp.Auth
      end

  The response forbids framing, to stop clickjacking of the consent page.
  """

  @behaviour Plug

  import Plug.Conn

  alias Gatekeep.Authorization

  @impl true
  def init(opts), do: Keyword.fetch!(opts, :gatekeep)

  @impl true
  def call(conn, gatekeep) do
    config = gatekeep.config()
    conn = conn |> fetch_query_params() |> put_resp_header("x-frame-options", "DENY")
    params = if conn.method == "GET", do: conn.query_params, else: conn.params

    case Authorization.check(config, params) do
      {:ok, request} -> consent!(config).handle_authorization(conn, request)
      {:redirect, url} -> redirect(conn, url)
      {:error, reason} -> error(conn, consent!(config), reason)
    end
  end

  defp consent!(%{consent: nil}),
    do: raise(ArgumentError, "Gatekeep.Plug.Authorize needs a :consent module in the config")

  defp consent!(%{consent: module}), do: module

  defp error(conn, module, reason) do
    if function_exported?(module, :handle_error, 2) do
      module.handle_error(conn, reason)
    else
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(400, "This sign-in link is not valid.")
      |> halt()
    end
  end

  @doc """
  Redirects the browser to `url`, as `Gatekeep.Authorization.approve/3` and
  `Gatekeep.Authorization.deny/2` return it.
  """
  @spec redirect(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def redirect(conn, url) do
    conn
    |> put_resp_header("location", url)
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("referrer-policy", "no-referrer")
    |> send_resp(302, "")
    |> halt()
  end
end
