defmodule AttestoPhoenix.Controller.RegistrationController do
  @moduledoc """
  OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591 §3).

  Handles `POST /oauth/register`. This module owns the HTTP and protocol-framing
  concerns only: it parses the RFC 7591 §2 client-metadata document, validates
  the requested metadata against the server's advertised policy, mints the
  client's credentials through the `Attesto` core, hands the validated,
  issuance-ready attributes to the host's persistence callback, and renders the
  RFC 7591 §3.2.1 client information response or the RFC 7591 §3.2.2 error body.
  It carries no business-domain logic; the client registry is owned entirely by
  the host through the `:register_client` callback resolved from
  `AttestoPhoenix.Config`.

  ## Disabled by default

  Dynamic registration is an open door: a successful request mints a new client
  from an otherwise unauthenticated POST. The library therefore mounts this
  endpoint only when the host opts in (`AttestoPhoenix.Router`'s
  `:registration` option) AND supplies a `:register_client` callback
  (`AttestoPhoenix.Config` raises at boot otherwise). Any admission control the
  host wants in front of registration - a registration access token
  (RFC 7591 §3), an allowlist, rate limiting - lives in the host pipeline ahead
  of this action; the library does not assume one.

  ## Wire contract

  `POST /oauth/register` with `application/json`: the request body is a JSON
  client-metadata document (RFC 7591 §3.1). Any other Content-Type is rejected
  as `invalid_client_metadata` rather than parsed through an unintended path. A
  metadata document carries nested arrays (`redirect_uris`, `grant_types`) that
  have no canonical form-encoded representation, so no form encoding is offered
  here.

  Recognised metadata members (RFC 7591 §2) include `redirect_uris`,
  `grant_types`, `token_endpoint_auth_method`, and a space-delimited `scope`
  string. The request is validated member by member against the server's policy
  inputs - the scope catalog (`AttestoPhoenix.Config`'s `:scopes_supported`),
  the supported grant types, and the supported token-endpoint auth methods -
  and the first failure is returned.

  ## Issued credentials

  This controller owns credential generation: it mints the `client_id` and (for
  a confidential client, i.e. any `token_endpoint_auth_method` other than
  `none`) a high-entropy `client_secret` via `Attesto.Secret` (RFC 6749 §2.3.1
  high-entropy secret). The plaintext secret appears in the RFC 7591 §3.2.1
  response exactly once, accompanied by the REQUIRED `client_secret_expires_at`
  (`0`, non-expiring); only its one-way hash is handed to the host for
  persistence, so a leaked client store yields no usable secret.

  ## Responses

  Success renders HTTP 201 with the RFC 7591 §3.2.1 client information response
  (the registered metadata plus the synthesised `client_id`, the optional
  `client_secret` with its REQUIRED `client_secret_expires_at`, and
  `client_id_issued_at`). Failure renders the RFC 7591
  §3.2.2 error body (`{"error": code, "error_description": ...}`) with the
  RFC 7591 §3.2.2 codes `invalid_redirect_uri` and `invalid_client_metadata`.
  A host store rejection surfaces as `invalid_client_metadata` (the request
  named a client the store would not accept) rather than a 500. Both success
  and error responses carry no-store cache headers (RFC 7234 §5.2) because the
  body can carry a freshly minted credential.

  ## Event

  A successful registration emits a `:client_registered` event (RFC 7591)
  through `AttestoPhoenix.Event` carrying the issued `client_id`. The plaintext
  secret is never placed on the event.
  """

  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Attesto.{Secret, SecureCompare}
  alias AttestoPhoenix.{Config, Event}

  # RFC 7234 §5.2: a credential-bearing response must never be cached.
  @cache_control_no_store "no-store"
  @pragma_no_cache "no-cache"

  # RFC 7591 §3.1: the registration request body is a JSON object.
  @content_type_json "application/json"

  # RFC 7591 §3.2.2 error codes.
  @error_invalid_redirect_uri "invalid_redirect_uri"
  @error_invalid_client_metadata "invalid_client_metadata"
  @error_invalid_token "invalid_token"

  # RFC 7591 §2 / RFC 6749 §2.1: a public client (token_endpoint_auth_method
  # "none") holds no secret; any other method designates a confidential client,
  # which is issued one. Absent the member, the client defaults to confidential
  # (RFC 7591 §2 default is client_secret_basic).
  @auth_method_none "none"
  @default_auth_method "client_secret_basic"

  # RFC 7591 §3.2.1: when a `client_secret` is issued, `client_secret_expires_at`
  # is REQUIRED in the client information response; `0` denotes a secret that
  # does not expire. This server issues non-expiring secrets.
  @client_secret_non_expiring 0

  # RFC 6749 §1.3 / §4: the grant types this server understands, against which a
  # requested `grant_types` member is checked when the host has not narrowed the
  # set via `:grant_types_supported`.
  @default_grant_types_supported ~w(authorization_code refresh_token client_credentials)

  # RFC 7591 §2: a grant type that issues an authorization code (and thus
  # redirects the resource owner back to the client) requires at least one
  # registered redirect URI (RFC 6749 §3.1.2). client_credentials does not.
  @redirect_requiring_grant_types ~w(authorization_code)

  # RFC 7591 §2: human-facing client metadata members carried through to the
  # host store so consent screens keep the client's identity. These are
  # display/identity strings; the controller validates only that each is a
  # string (their trust level is the host's, never the library's).
  @display_string_metadata ~w(client_name client_uri logo_uri tos_uri policy_uri
                              jwks_uri software_id software_version software_statement)

  # RFC 7591 §2 `contacts`: an array of strings (e.g. email addresses) carried
  # through to the host store.
  @string_array_metadata ~w(contacts)

  # RFC 7591 §2 `jwks`: the client's inline public JWK Set. It is carried
  # through to the host store so authorization and token endpoints can verify
  # request objects and private_key_jwt assertions without resolving jwks_uri.
  @map_metadata ~w(jwks)

  @doc """
  Dynamic client registration action (RFC 7591 §3.1).

  Validates the client-metadata document, mints the client's credentials,
  persists via the host callback, and renders either the RFC 7591 §3.2.1
  client information response or an RFC 7591 §3.2.2 error. Every response
  carries no-store cache headers (RFC 7234 §5.2).
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, _params) do
    conn = put_no_store_headers(conn)
    config = config(conn)
    metadata = registration_metadata(conn)

    with :ok <- check_content_type(conn),
         {:ok, validated} <- validate_metadata(metadata, config),
         {:ok, issued} <- issue_client(validated, config),
         {:ok, _stored} <- persist(issued, config) do
      emit_registered(conn, config, issued)

      conn
      |> put_status(:created)
      |> json(client_information_response(issued))
    else
      {:error, %{} = error} -> render_error(conn, error)
    end
  end

  @doc """
  Dynamic client registration management delete action (RFC 7592 §2).

  The OpenID conformance suite uses this as cleanup for dynamically registered
  clients. A host must wire both `:client_registration_access_token_hash` and
  `:unregister_client`; absent either callback, the endpoint fails closed.
  """
  @spec delete(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def delete(conn, %{"client_id" => client_id}) when is_binary(client_id) do
    conn = put_no_store_headers(conn)
    config = config(conn)

    with {:ok, token} <- registration_bearer_token(conn),
         {:ok, client} <- invoke(config.load_client, [client_id]),
         :ok <- verify_registration_access_token(config, client, token),
         :ok <- unregister_client(config, client) do
      send_resp(conn, :no_content, "")
    else
      {:error, %{} = error} -> render_error(conn, error)
      _ -> render_error(conn, invalid_registration_token_error())
    end
  end

  # ── Configuration ────────────────────────────────────────────────────────

  # The per-request config is placed on the conn by the host pipeline (the same
  # mechanism the other authorization-server controllers rely on). It is a
  # validated `AttestoPhoenix.Config` struct read by field; this controller
  # holds no policy of its own.
  defp config(%Plug.Conn{private: %{attesto_phoenix_config: %Config{} = config}}), do: config

  # ── Request parsing ──────────────────────────────────────────────────────

  # RFC 7591 §3.1: the metadata document is the JSON request body. Read it from
  # the parsed body only; a query-string copy would leak into proxy logs and is
  # not part of the wire contract.
  defp registration_metadata(%Plug.Conn{body_params: body}) when is_map(body), do: body
  defp registration_metadata(_conn), do: %{}

  defp check_content_type(conn) do
    case get_req_header(conn, "content-type") do
      [] ->
        # No body parser ran; the empty document fails metadata validation
        # below, not here.
        :ok

      [value | _] ->
        type =
          value
          |> String.split(";", parts: 2)
          |> List.first()
          |> String.trim()
          |> String.downcase()

        if type == @content_type_json do
          :ok
        else
          {:error,
           error(
             @error_invalid_client_metadata,
             "registration requests must be #{@content_type_json} (RFC 7591 §3.1)"
           )}
        end
    end
  end

  # ── Metadata validation (RFC 7591 §2) ────────────────────────────────────

  # Validate each requested metadata member against the server's advertised
  # policy and return the normalised, validated metadata. The first failing
  # check stops validation (RFC 7591 §3.2.2) so the client learns which member
  # was rejected.
  defp validate_metadata(metadata, config) do
    with {:ok, auth_method} <- validate_auth_method(metadata, config),
         {:ok, grant_types} <- validate_grant_types(metadata, config),
         {:ok, redirect_uris} <- validate_redirect_uris(metadata, grant_types),
         {:ok, scope} <- validate_scope(metadata, config),
         {:ok, passthrough} <- validate_passthrough_metadata(metadata) do
      core = %{
        "token_endpoint_auth_method" => auth_method,
        "grant_types" => grant_types,
        "redirect_uris" => redirect_uris,
        "scope" => scope
      }

      # The known RFC 7591 §2 display/identity members are merged UNDER the
      # protocol-critical members so a request can never override the validated
      # auth method, grants, redirect URIs, or scope through a passthrough key.
      {:ok, Map.merge(passthrough, core)}
    end
  end

  # RFC 7591 §2: validate and carry through the KNOWN client-identity metadata
  # members (client_name, client_uri, logo_uri, contacts, policy_uri, tos_uri,
  # ...) so consent screens keep the client's identity. Only members on the
  # explicit allowlist are passed through; an unknown field is dropped and
  # never promoted to trusted policy. The first malformed known member stops
  # validation with `invalid_client_metadata` (RFC 7591 §3.2.2).
  defp validate_passthrough_metadata(metadata) do
    Enum.reduce_while(passthrough_specs(), {:ok, %{}}, fn {key, kind}, {:ok, acc} ->
      case validate_passthrough_member(metadata, key, kind) do
        :absent -> {:cont, {:ok, acc}}
        {:ok, value} -> {:cont, {:ok, Map.put(acc, key, value)}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  # The allowlist of known RFC 7591 §2 members carried through, each paired
  # with the shape it must satisfy.
  defp passthrough_specs do
    Enum.map(@display_string_metadata, &{&1, :string}) ++
      Enum.map(@string_array_metadata, &{&1, :string_array}) ++
      Enum.map(@map_metadata, &{&1, :map})
  end

  defp validate_passthrough_member(metadata, key, kind) do
    case Map.get(metadata, key) do
      nil -> :absent
      value -> validate_passthrough_value(key, kind, value)
    end
  end

  defp validate_passthrough_value(_key, :string, value) when is_binary(value), do: {:ok, value}

  defp validate_passthrough_value(key, :string, _value) do
    {:error, error(@error_invalid_client_metadata, "#{key} must be a string (RFC 7591 §2)")}
  end

  defp validate_passthrough_value(_key, :string_array, value) when is_list(value) do
    if Enum.all?(value, &is_binary/1) do
      {:ok, value}
    else
      {:error,
       error(@error_invalid_client_metadata, "contacts must be an array of strings (RFC 7591 §2)")}
    end
  end

  defp validate_passthrough_value(key, :string_array, _value) do
    {:error, error(@error_invalid_client_metadata, "#{key} must be an array (RFC 7591 §2)")}
  end

  defp validate_passthrough_value(_key, :map, value) when is_map(value), do: {:ok, value}

  defp validate_passthrough_value(key, :map, _value) do
    {:error, error(@error_invalid_client_metadata, "#{key} must be an object (RFC 7591 §2)")}
  end

  # RFC 7591 §2 / RFC 6749 §2.3.1: the token-endpoint auth method must be one
  # the server supports. Absent, it defaults to client_secret_basic.
  defp validate_auth_method(metadata, config) do
    supported = token_endpoint_auth_methods_supported(config)

    case Map.get(metadata, "token_endpoint_auth_method") do
      nil ->
        {:ok, @default_auth_method}

      method when is_binary(method) ->
        if method in supported do
          {:ok, method}
        else
          {:error,
           error(
             @error_invalid_client_metadata,
             "token_endpoint_auth_method #{inspect(method)} is not supported"
           )}
        end

      _ ->
        {:error,
         error(@error_invalid_client_metadata, "token_endpoint_auth_method must be a string")}
    end
  end

  # RFC 7591 §2: every requested grant type must be one the server supports
  # (RFC 6749 §1.3). Absent, the client is registered with no grant types; the
  # host store decides whether that is acceptable.
  defp validate_grant_types(metadata, config) do
    supported = grant_types_supported(config)

    case Map.get(metadata, "grant_types") do
      nil ->
        {:ok, []}

      grant_types when is_list(grant_types) ->
        case Enum.reject(grant_types, &(&1 in supported)) do
          [] ->
            {:ok, grant_types}

          [unsupported | _] ->
            {:error,
             error(
               @error_invalid_client_metadata,
               "grant_type #{inspect(unsupported)} is not supported"
             )}
        end

      _ ->
        {:error, error(@error_invalid_client_metadata, "grant_types must be an array")}
    end
  end

  # RFC 7591 §2 / RFC 6749 §3.1.2: a grant type that redirects the resource
  # owner back to the client requires at least one absolute redirect URI; a
  # malformed or relative URI is rejected as invalid_redirect_uri.
  defp validate_redirect_uris(metadata, grant_types) do
    redirect_uris = Map.get(metadata, "redirect_uris")
    needs_redirect? = Enum.any?(grant_types, &(&1 in @redirect_requiring_grant_types))

    cond do
      is_nil(redirect_uris) and needs_redirect? ->
        {:error,
         error(
           @error_invalid_redirect_uri,
           "redirect_uris is required for the requested grant_types (RFC 6749 §3.1.2)"
         )}

      is_nil(redirect_uris) ->
        {:ok, []}

      is_list(redirect_uris) ->
        validate_redirect_uri_list(redirect_uris, needs_redirect?)

      true ->
        {:error, error(@error_invalid_redirect_uri, "redirect_uris must be an array")}
    end
  end

  defp validate_redirect_uri_list([], true) do
    {:error,
     error(
       @error_invalid_redirect_uri,
       "redirect_uris must not be empty for the requested grant_types (RFC 6749 §3.1.2)"
     )}
  end

  defp validate_redirect_uri_list(redirect_uris, _needs_redirect?) do
    case Enum.find(redirect_uris, &(not absolute_uri?(&1))) do
      nil ->
        {:ok, redirect_uris}

      bad ->
        {:error, error(@error_invalid_redirect_uri, "redirect_uri #{inspect(bad)} is invalid")}
    end
  end

  # RFC 6749 §3.1.2: a redirect URI must be an absolute URI (scheme + host).
  defp absolute_uri?(value) when is_binary(value) do
    case URI.new(value) do
      {:ok, %URI{scheme: scheme, host: host}} ->
        is_binary(scheme) and scheme != "" and is_binary(host) and host != ""

      _ ->
        false
    end
  end

  defp absolute_uri?(_value), do: false

  # RFC 7591 §2 / RFC 6749 §3.3: the requested scope is a space-delimited
  # string; every requested scope must be in the server's catalog
  # (`:scopes_supported`). Absent, the client registers with no scope.
  defp validate_scope(metadata, config) do
    case Map.get(metadata, "scope") do
      nil ->
        {:ok, nil}

      scope when is_binary(scope) ->
        requested = String.split(scope, " ", trim: true)
        catalog = config.scopes_supported || []

        case Enum.reject(requested, &(&1 in catalog)) do
          [] ->
            {:ok, scope}

          [unknown | _] ->
            {:error,
             error(@error_invalid_client_metadata, "scope #{inspect(unknown)} is unknown")}
        end

      _ ->
        {:error, error(@error_invalid_client_metadata, "scope must be a space-delimited string")}
    end
  end

  # ── Credential issuance ──────────────────────────────────────────────────

  # Mint the client identifier and (for a confidential client) the client
  # secret. The plaintext secret is held only long enough to put it in the
  # response and its hash in the persisted attributes; it is never logged or
  # evented. `client_id_issued_at` is the RFC 7591 §3.2.1 issuance time.
  defp issue_client(validated, config) do
    client_id = Secret.generate()
    client_secret = generate_secret(Map.fetch!(validated, "token_endpoint_auth_method"))
    registration_access_token = Secret.generate()

    issued =
      validated
      |> Map.put("client_id", client_id)
      |> Map.put("client_id_issued_at", System.system_time(:second))
      |> Map.put("registration_access_token", registration_access_token)
      |> Map.put("registration_client_uri", Config.registration_client_uri(config, client_id))
      |> put_client_secret(client_secret)

    {:ok, issued}
  end

  # RFC 6749 §2.1: a public client holds no secret.
  defp generate_secret(@auth_method_none), do: nil
  defp generate_secret(_confidential_method), do: Secret.generate()

  # RFC 7591 §3.2.1: `client_secret` and, when a secret is issued,
  # `client_secret_expires_at` are returned together. The latter is REQUIRED in
  # the response whenever a `client_secret` is present; `0` signals a secret that
  # does not expire. A public client (no secret) carries neither member.
  defp put_client_secret(issued, nil), do: issued

  defp put_client_secret(issued, secret) do
    issued
    |> Map.put("client_secret", secret)
    |> Map.put("client_secret_expires_at", @client_secret_non_expiring)
  end

  # ── Persistence (host-owned) ─────────────────────────────────────────────

  # Hand the validated, issuance-ready metadata to the host persistence
  # callback. The host owns the client registry; the library never touches it.
  # The plaintext client_secret is replaced with its one-way hash before
  # persistence so the store never holds the bearer value (RFC 6749 §2.3.1).
  defp persist(issued, config) do
    case invoke(config.register_client, [persistable_attrs(issued)]) do
      {:ok, stored} ->
        {:ok, stored}

      {:error, _reason} ->
        # A store-level rejection (constraint violation, unacceptable metadata)
        # is a client problem, not a server fault: render it as RFC 7591 §3.2.2
        # invalid_client_metadata rather than a 500.
        {:error,
         error(@error_invalid_client_metadata, "the requested client could not be registered")}
    end
  end

  defp persistable_attrs(issued) do
    issued
    |> put_client_secret_hash()
    |> put_registration_access_token_hash()
    # Response-only members (RFC 7591 §3.2.1 / RFC 7592 §2.1), not client
    # metadata, so they are not handed to the host persistence callback.
    |> Map.delete("client_secret")
    |> Map.delete("client_secret_expires_at")
    |> Map.delete("registration_access_token")
    |> Map.delete("registration_client_uri")
  end

  defp put_client_secret_hash(issued) do
    case Map.get(issued, "client_secret") do
      nil -> issued
      plaintext -> Map.put(issued, "client_secret_hash", Secret.hash(plaintext))
    end
  end

  defp put_registration_access_token_hash(issued) do
    case Map.get(issued, "registration_access_token") do
      token when is_binary(token) ->
        Map.put(issued, "registration_access_token_hash", Secret.hash(token))

      _ ->
        issued
    end
  end

  # ── Response (RFC 7591 §3.2.1) ───────────────────────────────────────────

  # The client information response is the validated metadata as registered:
  # it carries the synthesised client_id, the plaintext client_secret (the one
  # and only time it is disclosed) with its RFC 7591 §3.2.1 REQUIRED
  # client_secret_expires_at, and client_id_issued_at. A `scope` of nil
  # (none requested) is omitted rather than serialised as JSON null.
  defp client_information_response(issued) do
    case Map.get(issued, "scope") do
      nil -> Map.delete(issued, "scope")
      _ -> issued
    end
  end

  # ── Event ────────────────────────────────────────────────────────────────

  # The event records WHICH client was registered, never the secret.
  defp emit_registered(_conn, config, issued) do
    Event.emit(config, :client_registered, %{client_id: Map.get(issued, "client_id")})
  end

  # ── Policy inputs ────────────────────────────────────────────────────────

  defp grant_types_supported(config) do
    case config_field(config, :grant_types_supported) do
      list when is_list(list) and list != [] -> list
      _ -> @default_grant_types_supported
    end
  end

  defp token_endpoint_auth_methods_supported(config) do
    case config_field(config, :token_endpoint_auth_methods_supported) do
      list when is_list(list) and list != [] -> list
      _ -> [@default_auth_method, @auth_method_none]
    end
  end

  # These two policy inputs are optional registration extensions to the core
  # config; read them defensively so a config struct without the field falls
  # back to the RFC defaults rather than crashing.
  defp config_field(config, key), do: Map.get(config, key)

  # ── Helpers ──────────────────────────────────────────────────────────────

  defp registration_bearer_token(conn) do
    with [header | _] <- get_req_header(conn, "authorization"),
         [scheme, token] when token != "" <- String.split(header, " ", parts: 2),
         true <- String.downcase(scheme) == "bearer" do
      {:ok, token}
    else
      _ ->
        {:error, invalid_registration_token_error()}
    end
  end

  defp verify_registration_access_token(config, client, token) do
    with callback when not is_nil(callback) <- config.client_registration_access_token_hash,
         hash when is_binary(hash) <- invoke(callback, [client]),
         true <- token |> Secret.hash() |> SecureCompare.equal?(hash) do
      :ok
    else
      _ -> {:error, invalid_registration_token_error()}
    end
  end

  defp unregister_client(config, client) do
    case config.unregister_client do
      nil ->
        {:error,
         error(
           @error_invalid_client_metadata,
           "dynamic client registration management is not configured"
         )}

      callback ->
        case invoke(callback, [client]) do
          :ok -> :ok
          {:ok, _client} -> :ok
          {:error, _reason} -> {:error, invalid_registration_token_error()}
        end
    end
  end

  defp invoke(fun, args) when is_function(fun), do: apply(fun, args)

  defp invoke({module, fun}, args) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, args)

  defp invoke({module, fun, extra}, args) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, args ++ extra)

  # ── Rendering (RFC 7591 §3.2.2) ──────────────────────────────────────────

  defp render_error(conn, %{error: code} = err) do
    conn
    |> put_status(Map.get(err, :status, 400))
    |> json(error_body(code, Map.get(err, :description)))
  end

  defp error_body(code, nil), do: %{error: code}
  defp error_body(code, description), do: %{error: code, error_description: description}

  defp error(code, description), do: %{error: code, description: description, status: 400}

  defp invalid_registration_token_error do
    %{
      error: @error_invalid_token,
      description: "registration access token is missing or invalid",
      status: 401
    }
  end

  defp put_no_store_headers(conn) do
    conn
    |> put_resp_header("cache-control", @cache_control_no_store)
    |> put_resp_header("pragma", @pragma_no_cache)
  end
end
