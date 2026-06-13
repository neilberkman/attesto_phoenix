defmodule AttestoPhoenix.RequestContext do
  @moduledoc """
  Neutral request-fact helpers the OAuth 2.0 / OIDC flows derive from a `Plug.Conn`.

  Authorization-server endpoints need a handful of transport-level facts that are
  not safe to read straight off the `Plug.Conn` when the listener sits behind a
  reverse proxy:

    * the **client IP**, honoring `X-Forwarded-For` only for trusted proxies;
    * whether the request effectively arrived over **HTTPS** (RFC 8446), honoring
      a trusted `X-Forwarded-Proto: https` hop;
    * the canonical request **URL** (`htu`) and **method** (`htm`) a DPoP proof is
      bound to, per RFC 9449 §4.2 / §4.3;
    * the peer **certificate DER** presented at the TLS layer, used for the
      RFC 8705 §3 mutual-TLS `cnf` binding.

  Every forwarded-header-derived fact is gated on a trusted-proxy allowlist. A
  request that arrives from a peer outside that allowlist with forged
  `X-Forwarded-*` headers is a spoofing attempt: the headers are dropped and the
  fact is derived from the direct connection only. This is fail-closed by
  construction, an untrusted peer cannot assert `https`, cannot redirect the
  DPoP `htu`, and cannot forge a client IP.

  The trust boundary, the HTTPS requirement, and the optional certificate
  extractor are read from `AttestoPhoenix.Config`; this module never hardcodes
  deployment policy.

  ## Trusted-proxy allowlist

  `config.trusted_proxies` controls whether `X-Forwarded-*` headers are honored.
  It accepts a list whose elements are any of:

    * `:loopback` - matches `127.0.0.0/8` and `::1`.
    * `:any` - matches every peer. Only safe when another mechanism (firewall,
      ingress ACL) guarantees that only the proxy can reach the app port. Prefer
      explicit CIDRs.
    * an IP tuple (`{10, 0, 0, 1}` / an 8-element IPv6 tuple) - exact match.
    * a binary CIDR string (`"10.0.0.0/8"`, `"::1/128"`) - subnet match.

  The default (`[]`) trusts no proxy, so forwarded headers are never honored
  unless the host opts in.
  """

  alias AttestoPhoenix.Callback
  alias AttestoPhoenix.Config

  # RFC 9449 §4.3: `htu` is the HTTP target URI of the request to which the DPoP
  # proof is attached, without query or fragment. The scheme/host/port that make
  # up that URI are the client-observed values, which behind a TLS-terminating
  # proxy live in the forwarded headers rather than on the inter-proxy hop.
  @forwarded_proto_header "x-forwarded-proto"
  @forwarded_host_header "x-forwarded-host"
  @forwarded_port_header "x-forwarded-port"
  @forwarded_for_header "x-forwarded-for"

  # IANA default ports per scheme; omitted from the canonical authority so the
  # `htu` matches what a client built from a bare `https://host/path` URL.
  @https_default_port 443
  @http_default_port 80

  @loopback_v4_cidr {{127, 0, 0, 0}, 8}
  @loopback_v6 {0, 0, 0, 0, 0, 0, 0, 1}

  @max_port 65_535

  @doc """
  Returns the client IP as a string, or `nil` if it cannot be determined.

  When the request comes from a trusted proxy and carries `X-Forwarded-For`, the
  left-most entry (the original client per RFC 7239 / the de-facto
  `X-Forwarded-For` convention) is returned. Otherwise the direct connection's
  `remote_ip` is used. An untrusted peer cannot forge the client IP this way: its
  `X-Forwarded-For` is ignored entirely.
  """
  @spec client_ip(Plug.Conn.t(), Config.t()) :: String.t() | nil
  def client_ip(%Plug.Conn{} = conn, %Config{} = config) do
    forwarded =
      if from_trusted_proxy?(conn, config) do
        first_forwarded_for(conn)
      end

    case forwarded do
      ip when is_binary(ip) -> ip
      _ -> remote_ip_string(conn)
    end
  end

  @doc """
  Returns `true` when the request effectively arrived over HTTPS.

  The effective scheme is the connection scheme, upgraded to `https` when a
  trusted proxy forwards `X-Forwarded-Proto: https`. An untrusted peer's
  forwarded scheme is ignored, so a plain-HTTP hop cannot masquerade as TLS.
  """
  @spec https?(Plug.Conn.t(), Config.t()) :: boolean()
  def https?(%Plug.Conn{} = conn, %Config{} = config) do
    effective_scheme(conn, config) == "https"
  end

  @doc """
  Returns `:ok` when the request satisfies the configured transport policy, or
  `{:error, :insecure_transport}` when `config.require_https` is set and the
  request did not effectively arrive over HTTPS.

  This is the fail-closed transport check the token and protected-resource
  endpoints run before touching a credential: a bearer token or client secret
  that has already crossed a plain-HTTP hop must be treated as compromised, so
  the request is refused rather than served or redirected (a redirect would have
  the client replay the exposed credential).
  """
  @spec check_https(Plug.Conn.t(), Config.t()) :: :ok | {:error, :insecure_transport}
  def check_https(%Plug.Conn{} = conn, %Config{} = config) do
    if config.require_https and not https?(conn, config) do
      {:error, :insecure_transport}
    else
      :ok
    end
  end

  @doc """
  Returns the HTTP method (`htm`) the DPoP proof is bound to, per RFC 9449 §4.2.

  The method is taken verbatim from the request; it is not derived from any
  forwarded header.
  """
  @spec http_method(Plug.Conn.t()) :: String.t()
  def http_method(%Plug.Conn{method: method}), do: method

  @doc """
  Returns the canonical request URL (`htu`) the DPoP proof is bound to, per
  RFC 9449 §4.3: the request URI without its query or fragment.

  When `config.htu` is set, that callback is used so a host can fully override
  URL reconstruction (e.g. for a proxy topology this module does not model).
  Otherwise the URL is built from the effective scheme/host/port, which honor
  `X-Forwarded-Proto` / `X-Forwarded-Host` / `X-Forwarded-Port` only when the
  request comes from a trusted proxy. An untrusted peer therefore cannot
  redirect the `htu` check by injecting forwarded headers: the URL falls back to
  the direct connection's authority and the proof either verifies against the
  real listener URL or fails on its signature.
  """
  @spec canonical_url(Plug.Conn.t(), Config.t()) :: String.t()
  def canonical_url(%Plug.Conn{} = conn, %Config{htu: htu} = config) when not is_nil(htu) do
    Callback.invoke(htu, [conn]) || canonical_url(conn, %{config | htu: nil})
  end

  def canonical_url(%Plug.Conn{} = conn, %Config{} = config) do
    trusted? = from_trusted_proxy?(conn, config)
    scheme = effective_scheme(conn, config)
    host = (trusted? && forwarded_host(conn)) || conn.host
    port = (trusted? && forwarded_port(conn)) || conn.port

    authority =
      if default_port?(scheme, port) do
        host
      else
        "#{host}:#{port}"
      end

    "#{scheme}://#{authority}#{conn.request_path}"
  end

  @doc """
  Returns the peer certificate DER for the RFC 8705 §3 mutual-TLS `cnf` binding,
  or `nil` when no client certificate was presented.

  When `config.cert_der` is set (required by `AttestoPhoenix.Config` whenever
  `mtls_enabled` is true), that callback extracts the DER; this is the supported
  override for proxy topologies that surface the client certificate in a header
  rather than on the TLS socket. Otherwise the certificate is read from the
  connection's peer data, which the underlying adapter populates when the TLS
  socket negotiated client authentication.
  """
  @spec cert_der(Plug.Conn.t(), Config.t()) :: binary() | nil
  def cert_der(%Plug.Conn{} = conn, %Config{cert_der: cert_der}) when not is_nil(cert_der) do
    case Callback.invoke(cert_der, [conn]) do
      der when is_binary(der) and byte_size(der) > 0 -> der
      _ -> nil
    end
  end

  def cert_der(%Plug.Conn{} = conn, %Config{}) do
    case Plug.Conn.get_peer_data(conn) do
      %{ssl_cert: der} when is_binary(der) and byte_size(der) > 0 -> der
      _ -> nil
    end
  rescue
    _ -> nil
  end

  @doc """
  Returns `true` when `conn.remote_ip` falls inside `config.trusted_proxies`.

  This is the single trust gate that governs whether any `X-Forwarded-*` header
  is honored. It is exposed so callers that need a custom forwarded-header read
  can apply the same boundary rather than re-implementing it and risking drift.
  """
  @spec from_trusted_proxy?(Plug.Conn.t(), Config.t()) :: boolean()
  def from_trusted_proxy?(%Plug.Conn{remote_ip: remote_ip}, %Config{trusted_proxies: proxies}) do
    # A connection with no resolved peer address is never trusted: there is no
    # IP to test against the allowlist, so it fails closed.
    is_tuple(remote_ip) and Enum.any?(List.wrap(proxies), &peer_matches?(remote_ip, &1))
  end

  # ----- effective scheme -----

  defp effective_scheme(conn, config) do
    forwarded = from_trusted_proxy?(conn, config) && forwarded_scheme(conn)

    case forwarded do
      scheme when is_binary(scheme) -> scheme
      _ -> Atom.to_string(conn.scheme)
    end
  end

  # ----- forwarded-header parsing -----

  # `X-Forwarded-For` is a comma-separated chain of proxied-through IPs; the
  # left-most entry is the original client. Only consulted for trusted peers.
  defp first_forwarded_for(conn) do
    conn
    |> first_header(@forwarded_for_header)
    |> case do
      value when is_binary(value) ->
        value
        |> String.split(",", parts: 2)
        |> List.first()
        |> String.trim()
        |> nil_if_empty()

      _ ->
        nil
    end
  end

  defp forwarded_scheme(conn) do
    conn
    |> first_forwarded_token(@forwarded_proto_header)
    |> case do
      value when is_binary(value) -> String.downcase(value)
      _ -> nil
    end
  end

  defp forwarded_host(conn), do: first_forwarded_token(conn, @forwarded_host_header)

  defp forwarded_port(conn) do
    conn
    |> first_forwarded_token(@forwarded_port_header)
    |> case do
      value when is_binary(value) ->
        case Integer.parse(value) do
          {port, ""} when port > 0 and port <= @max_port -> port
          _ -> nil
        end

      _ ->
        nil
    end
  end

  # A forwarded header may itself be a comma-separated chain when multiple
  # proxies appended values; take the left-most (closest to the client) token.
  defp first_forwarded_token(conn, header) do
    conn
    |> first_header(header)
    |> case do
      value when is_binary(value) ->
        value
        |> String.split(",", parts: 2)
        |> List.first()
        |> String.trim()
        |> nil_if_empty()

      _ ->
        nil
    end
  end

  defp first_header(conn, header) do
    case Plug.Conn.get_req_header(conn, header) do
      [value | _] -> value
      _ -> nil
    end
  end

  defp nil_if_empty(""), do: nil
  defp nil_if_empty(value), do: value

  # ----- authority helpers -----

  defp default_port?("https", @https_default_port), do: true
  defp default_port?("http", @http_default_port), do: true
  defp default_port?(_scheme, _port), do: false

  defp remote_ip_string(%Plug.Conn{remote_ip: nil}), do: nil

  defp remote_ip_string(%Plug.Conn{remote_ip: remote_ip}) do
    case :inet.ntoa(remote_ip) do
      {:error, _} -> nil
      charlist -> List.to_string(charlist)
    end
  rescue
    _ -> nil
  end

  # ----- trusted-proxy matching -----

  defp peer_matches?(_remote_ip, :any), do: true

  defp peer_matches?(remote_ip, :loopback) do
    cidr_contains?(@loopback_v4_cidr, remote_ip) or remote_ip == @loopback_v6
  end

  defp peer_matches?(remote_ip, ip) when is_tuple(ip), do: remote_ip == ip

  defp peer_matches?(remote_ip, cidr) when is_binary(cidr) do
    case parse_cidr(cidr) do
      {:ok, parsed} -> cidr_contains?(parsed, remote_ip)
      :error -> false
    end
  end

  defp peer_matches?(_remote_ip, _other), do: false

  # Parse `"<address>/<prefix>"` into `{network_tuple, prefix_len}`. An address
  # with no `/` is treated as a host route (full-length prefix). A malformed
  # entry returns `:error` and is treated as "does not match" rather than
  # raising; misconfiguration must not crash request handling, and a non-match
  # is the fail-closed outcome (the peer is not trusted).
  defp parse_cidr(cidr) do
    case String.split(cidr, "/", parts: 2) do
      [address, prefix] ->
        with {:ok, ip} <- parse_address(address),
             {prefix_len, ""} <- Integer.parse(prefix),
             true <- valid_prefix?(ip, prefix_len) do
          {:ok, {ip, prefix_len}}
        else
          _ -> :error
        end

      [address] ->
        case parse_address(address) do
          {:ok, ip} -> {:ok, {ip, full_prefix(ip)}}
          :error -> :error
        end
    end
  end

  defp parse_address(address) do
    case :inet.parse_address(String.to_charlist(address)) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> :error
    end
  end

  defp full_prefix(ip) when tuple_size(ip) == 4, do: 32
  defp full_prefix(ip) when tuple_size(ip) == 8, do: 128

  defp valid_prefix?(ip, prefix_len) when tuple_size(ip) == 4, do: prefix_len in 0..32

  defp valid_prefix?(ip, prefix_len) when tuple_size(ip) == 8, do: prefix_len in 0..128

  # Containment by integer masking. The network and the candidate must be the
  # same address family (both IPv4 or both IPv6) to match; an IPv4 peer never
  # matches an IPv6 CIDR or vice versa.
  defp cidr_contains?({network, prefix_len}, candidate) when tuple_size(network) == tuple_size(candidate) do
    mask = bitmask(full_prefix(network), prefix_len)
    Bitwise.band(ip_to_integer(network), mask) == Bitwise.band(ip_to_integer(candidate), mask)
  end

  defp cidr_contains?(_network, _candidate), do: false

  # All host bits cleared: a `prefix_len`-bit network mask over a `total_bits`
  # address space.
  defp bitmask(total_bits, prefix_len) do
    host_bits = total_bits - prefix_len
    Bitwise.bsl(Bitwise.bsl(1, prefix_len) - 1, host_bits)
  end

  defp ip_to_integer(ip) when tuple_size(ip) == 4 do
    ip
    |> Tuple.to_list()
    |> Enum.reduce(0, fn octet, acc -> acc * 256 + octet end)
  end

  defp ip_to_integer(ip) when tuple_size(ip) == 8 do
    ip
    |> Tuple.to_list()
    |> Enum.reduce(0, fn group, acc -> acc * 65_536 + group end)
  end
end
