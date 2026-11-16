defmodule Gatekeep.Util do
  @moduledoc false

  @doc "Current Unix time in seconds."
  def now, do: System.system_time(:second)

  @doc "Current time as a `DateTime` truncated to the second."
  def now_dt, do: DateTime.utc_now() |> DateTime.truncate(:second)

  @doc "`seconds` from now as a `DateTime` truncated to the second."
  def in_seconds(seconds), do: now_dt() |> DateTime.add(seconds)

  @doc "A random token with 256 bits of entropy."
  def random_token(prefix),
    do: prefix <> (:crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false))

  @doc "The SHA-256 digest stored in place of a token."
  def hash(value) when is_binary(value), do: :crypto.hash(:sha256, value)

  def expect(true), do: :ok
  def expect(_), do: :error

  def expect(true, _reason), do: :ok
  def expect(_, reason), do: {:error, reason}

  @doc "Space-separated scope string to a list, without duplicates."
  def split_scope(nil), do: []

  def split_scope(scope) when is_binary(scope),
    do: scope |> String.split(" ", trim: true) |> Enum.uniq()

  def split_scope(_), do: []

  @doc """
  The canonical form of a URL for comparing resource indicators and issuers:
  lowercase scheme and host, no default port, and no trailing slash. Returns
  `:invalid` for URLs with a query, a fragment, or credentials.
  """
  def canonical_url(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host, query: nil, fragment: nil, userinfo: nil} = uri
      when is_binary(scheme) and is_binary(host) and host != "" ->
        scheme = String.downcase(scheme)
        port = if uri.port in [nil, URI.default_port(scheme)], do: "", else: ":#{uri.port}"
        "#{scheme}://#{String.downcase(host)}#{port}#{String.trim_trailing(uri.path || "", "/")}"

      _ ->
        :invalid
    end
  end

  def canonical_url(_), do: :invalid

  @doc "Whether two URLs name the same resource; see `canonical_url/1`."
  def same_url?(a, b) do
    case canonical_url(a) do
      :invalid -> false
      canonical -> canonical == canonical_url(b)
    end
  end
end
