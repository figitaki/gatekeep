defmodule Gatekeep.Consent do
  @moduledoc """
  The application's side of the authorization endpoint: who the user is,
  and whether they approve.

  `Gatekeep.Plug.Authorize` checks the authorization request, then calls
  `c:handle_authorization/2` with the `conn` and a `t:request/0`. The module
  owns everything the user sees: a sign-in page, an account or identity
  picker, the consent page. When the user decides, it calls
  `Gatekeep.Authorization.approve/3` or `Gatekeep.Authorization.deny/2`,
  which return the redirect back to the client, and sends it with
  `Gatekeep.Plug.Authorize.redirect/2`.

  A minimal module that shows a Phoenix consent page:

      defmodule MyAppWeb.Consent do
        @behaviour Gatekeep.Consent

        @impl true
        def handle_authorization(conn, request) do
          case conn.assigns[:current_user] do
            nil -> Phoenix.Controller.redirect(conn, to: "/log-in?return_to=" <> conn.request_path <> "?" <> conn.query_string)
            user -> Phoenix.Controller.render(conn, MyAppWeb.ConsentHTML, :show, request: request, user: user)
          end
        end
      end

  and the controller action that the consent form posts to:

      def decide(conn, %{"decision" => "approve"} = params) do
        {:ok, request} = Gatekeep.Authorization.check(MyApp.Auth.config(), params)

        {:ok, redirect} =
          Gatekeep.Authorization.approve(MyApp.Auth.config(), request,
            subject: "user:" <> to_string(conn.assigns.current_user.id),
            scopes: params["scopes"]
          )

        Gatekeep.Plug.Authorize.redirect(conn, redirect)
      end

  The consent form must carry the original authorization parameters
  (`request.params`) so the decision can check them again; it must also be
  protected against CSRF like any other form. Never approve on a GET.
  """

  @typedoc """
  A checked authorization request:

    * `client` - the `Gatekeep.Client`. Show `Gatekeep.Client.label/1`: the
      verified host of a metadata document client, or a registered client's
      self-chosen, unverified name.
    * `resource` - the `Gatekeep.Resource` the token will be for.
    * `scopes` - the requested scopes, which the user may narrow.
    * `scope_descriptions` - descriptions of those scopes for the page.
    * `params` - the authorization parameters to carry through the form.
  """
  @type request :: Gatekeep.Authorization.request()

  @doc "Handles a valid authorization request: sign the user in and ask for consent."
  @callback handle_authorization(Plug.Conn.t(), request()) :: Plug.Conn.t()

  @doc """
  Renders an error that must not redirect, because the client or its
  redirect URI can't be trusted. `reason` is `:invalid_client`,
  `:invalid_redirect_uri`, or `:invalid_request` (a registered client's bad
  request, shown here so the endpoint is not an open redirector). Defaults to
  a plain-text 400.
  """
  @callback handle_error(Plug.Conn.t(), reason :: atom()) :: Plug.Conn.t()

  @optional_callbacks handle_error: 2
end
