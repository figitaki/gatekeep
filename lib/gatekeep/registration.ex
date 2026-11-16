defmodule Gatekeep.Registration do
  @moduledoc """
  Dynamic client registration (RFC 7591), the fallback for clients without a
  client ID metadata document, such as the MCP Inspector.

  Registered clients are public: no secret, PKCE on every authorization.
  Their `client_id` starts with `gkc_`, and the name they give is never shown
  as verified. Errors in their authorization requests are shown on the
  issuer's own page rather than redirected, since anyone can register any
  redirect URI.

  Registration is on while an enabled resource takes public clients
  (`client_auth_methods` includes `"none"`).
  """

  alias Gatekeep.{Clients, Config, Storage, Util}

  @max_redirect_uris 10
  @max_uri_length 2_000

  @doc """
  Registers a public client. Returns the registration response, or an
  RFC 7591 error code and description.
  """
  @spec register(Config.t(), term()) ::
          {:ok, map()} | {:error, String.t(), String.t()} | {:error, :not_found}
  def register(%Config{} = config, params) do
    cond do
      not Config.public_clients?(config) -> {:error, :not_found}
      is_map(params) -> do_register(config, params)
      true -> {:error, "invalid_client_metadata", "Send a JSON object."}
    end
  end

  defp do_register(config, params) do
    redirect_uris = params["redirect_uris"]
    auth_method = Map.get(params, "token_endpoint_auth_method", "none")
    grant_types = Map.get(params, "grant_types", ["authorization_code"])
    response_types = Map.get(params, "response_types", ["code"])

    cond do
      not valid_redirect_uris?(redirect_uris) ->
        {:error, "invalid_redirect_uri", "Give 1 to 10 HTTPS, loopback, or app redirect URIs."}

      auth_method != "none" ->
        {:error, "invalid_client_metadata",
         "Only public clients (token_endpoint_auth_method \"none\") can register."}

      not (is_list(grant_types) and "authorization_code" in grant_types and
               grant_types -- ["authorization_code", "refresh_token"] == []) ->
        {:error, "invalid_client_metadata", "Use the authorization_code grant."}

      response_types != ["code"] ->
        {:error, "invalid_client_metadata", "Use response_type \"code\"."}

      true ->
        now = Util.now_dt()
        client_id = "gkc_" <> (:crypto.strong_rand_bytes(18) |> Base.url_encode64(padding: false))
        name = client_name(params["client_name"])

        :ok =
          Storage.call(config, :insert_client, [
            %{
              client_id: client_id,
              client_name: name,
              redirect_uris: redirect_uris,
              inserted_at: now
            }
          ])

        {:ok,
         %{
           "client_id" => client_id,
           "client_id_issued_at" => DateTime.to_unix(now),
           "client_name" => name,
           "redirect_uris" => redirect_uris,
           "token_endpoint_auth_method" => "none",
           "grant_types" => ["authorization_code", "refresh_token"],
           "response_types" => ["code"]
         }
         |> Map.reject(fn {_k, v} -> is_nil(v) end)}
    end
  end

  defp client_name(name) when is_binary(name) and name != "", do: String.slice(name, 0, 120)
  defp client_name(_), do: nil

  defp valid_redirect_uris?(uris) when is_list(uris) and uris != [],
    do: length(uris) <= @max_redirect_uris and Enum.all?(uris, &valid_redirect_uri?/1)

  defp valid_redirect_uris?(_), do: false

  @doc """
  Whether a registered client may use `uri`: HTTPS, an HTTP loopback address
  (RFC 8252 §7.3), or an app's private-use scheme (RFC 8252 §7.1). Never a
  fragment, credentials, or a scheme a browser runs.
  """
  @spec valid_redirect_uri?(term()) :: boolean()
  def valid_redirect_uri?(uri) when is_binary(uri) and byte_size(uri) <= @max_uri_length do
    case URI.new(uri) do
      {:ok, %URI{fragment: nil, userinfo: nil, scheme: scheme} = parsed} when is_binary(scheme) ->
        case String.downcase(scheme) do
          "https" -> is_binary(parsed.host) and parsed.host != ""
          "http" -> Clients.loopback_redirect?(uri)
          s when s in ~w(javascript data file vbscript about blob ws wss ftp) -> false
          s -> s =~ ~r/\A[a-z][a-z0-9+.-]*\z/
        end

      _ ->
        false
    end
  end

  def valid_redirect_uri?(_), do: false
end
