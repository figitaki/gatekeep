defmodule Gatekeep.Token do
  @moduledoc """
  The resource side: checks an access token presented to a protected
  resource.

  `authenticate/3` accepts a token only when:

    * it is known, unexpired, unrevoked, and so is its grant, so revoking the
      grant takes effect on the next request;
    * its audience is the resource checking it (RFC 8707): a token issued for
      one resource is refused by every other;
    * its client is not blocked;
    * a DPoP-bound token comes with `Authorization: DPoP` and a valid proof
      from the bound key, covering the token with `ath`; a bound token sent
      as Bearer is refused, so a stolen token is useless without the key.
      A proof that fails its checks is `:invalid_dpop_proof`; a valid proof
      from another key is `:invalid_token` (RFC 9449 §7.1);
    * a resource with `dpop: :required` gets a DPoP-bound token.

  `Gatekeep.Plug.Resource` wraps it with the HTTP challenges.
  """

  alias Gatekeep.{Config, DPoP, Resource, Storage, Util}

  defstruct [
    :client_id,
    :subject,
    :owner,
    :resource,
    :scopes,
    :claims,
    :grant_id,
    :dpop_jkt,
    :expires_at
  ]

  @type t :: %__MODULE__{
          client_id: String.t(),
          subject: String.t(),
          owner: String.t() | nil,
          resource: String.t(),
          scopes: [String.t()],
          claims: map(),
          grant_id: term(),
          dpop_jkt: String.t() | nil,
          expires_at: DateTime.t()
        }

  @typedoc """
  The credentials of a request: its `Authorization` header, every `DPoP`
  header value, its method, and its path (the proof's `htu` is the path on
  the resource's configured origin, never the Host header).
  """
  @type request :: %{
          authorization: String.t() | nil,
          dpop: [String.t()],
          method: String.t(),
          path: String.t()
        }

  @type error :: :missing_token | :invalid_token | :invalid_dpop_proof

  @doc """
  Authenticates the request's access token for `resource`, a resource
  identifier or `Gatekeep.Resource`. `:missing_token` means the request sent
  none; challenge it without an error code (RFC 6750 §3.1).
  """
  @spec authenticate(Config.t(), String.t() | Resource.t(), request()) ::
          {:ok, t()} | {:error, error()}
  def authenticate(%Config{} = config, resource, request) do
    with {:ok, %Resource{} = resource} <- fetch_resource(config, resource),
         {:ok, scheme, token} <- credentials(request[:authorization]),
         {:ok, record} <- lookup(config, resource, token),
         :ok <- check_binding(config, resource, record, scheme, token, request) do
      maybe_touch(config, record.grant)

      {:ok,
       %__MODULE__{
         client_id: record.client_id,
         subject: record.subject,
         owner: record.grant && record.grant[:owner],
         resource: record.resource,
         scopes: record.scopes,
         claims: (record.grant && record.grant[:claims]) || %{},
         grant_id: record.grant_id,
         dpop_jkt: record.dpop_jkt,
         expires_at: record.expires_at
       }}
    end
  end

  defp fetch_resource(_config, %Resource{} = resource), do: {:ok, resource}

  defp fetch_resource(config, id) do
    case Config.resource(config, id) do
      nil -> raise ArgumentError, "#{inspect(id)} is not a configured Gatekeep resource"
      resource -> {:ok, resource}
    end
  end

  @doc false
  # The scheme and token of an Authorization header. Schemes compare without
  # case (RFC 9110 §11.1).
  def credentials(header) when is_binary(header) do
    case String.split(header, " ", parts: 2) do
      [scheme, token] when token != "" ->
        case String.downcase(scheme) do
          "bearer" -> {:ok, :bearer, String.trim(token)}
          "dpop" -> {:ok, :dpop, String.trim(token)}
          _ -> {:error, :missing_token}
        end

      _ ->
        {:error, :missing_token}
    end
  end

  def credentials(_), do: {:error, :missing_token}

  defp lookup(config, resource, token) do
    now = DateTime.utc_now()

    with {:ok, record} <- Storage.call(config, :get_access_token, [Util.hash(token)]),
         true <- is_nil(record.revoked_at),
         :gt <- DateTime.compare(record.expires_at, now),
         true <- Util.same_url?(record.resource, resource.id),
         true <- resource.enabled,
         true <- grant_active?(record.grant),
         false <- record.client_id in config.blocked_clients do
      {:ok, record}
    else
      _ -> {:error, :invalid_token}
    end
  end

  defp grant_active?(nil), do: true
  defp grant_active?(grant), do: is_nil(grant.revoked_at)

  defp check_binding(config, resource, record, scheme, token, request) do
    case {record.dpop_jkt, scheme} do
      {nil, :dpop} ->
        {:error, :invalid_token}

      {nil, :bearer} ->
        if resource.dpop == :required, do: {:error, :invalid_token}, else: :ok

      {_jkt, :bearer} ->
        {:error, :invalid_token}

      {jkt, :dpop} ->
        proof_request = %{
          method: request.method,
          url: Resource.url_for(resource, request.path),
          access_token: token
        }

        # A valid proof from another key is a bad key binding, so the token
        # is what's wrong (RFC 9449 §7.1, Figure 16); invalid_dpop_proof is
        # for proofs that fail the checks of §4.3.
        case DPoP.verify(Map.get(request, :dpop, []), proof_request, config) do
          {:ok, ^jkt} -> :ok
          {:ok, _other_key} -> {:error, :invalid_token}
          {:error, _reason} -> {:error, :invalid_dpop_proof}
        end
    end
  end

  defp maybe_touch(_config, nil), do: :ok

  defp maybe_touch(config, grant) do
    now = Util.now_dt()

    if is_nil(grant[:last_used_at]) or DateTime.diff(now, grant.last_used_at) > 60,
      do: Storage.call(config, :touch_grant, [grant.id, now])

    :ok
  end

  @doc "Whether the token holds every scope in `scopes`."
  @spec has_scopes?(t(), [String.t()]) :: boolean()
  def has_scopes?(%__MODULE__{scopes: held}, scopes), do: scopes -- held == []
end
