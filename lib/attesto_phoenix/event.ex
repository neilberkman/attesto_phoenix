defmodule AttestoPhoenix.Event do
  @moduledoc """
  Neutral event struct and dispatcher for the optional `:on_event` callback.

  An OAuth 2.0 / OIDC authorization server takes many decisions that an
  operator may wish to record: a token was issued, a token request was denied,
  a token was revoked (RFC 7009), a refresh token was rotated (RFC 6749 §6),
  presented refresh-token reuse was detected (RFC 6819 §5.2.2.3), a bearer
  token authenticated a request (RFC 6750), a request was rejected, or a client
  was registered (RFC 7591). *Recording* those decisions (to a log, a database,
  a SIEM) is host policy, not a concern of this library. This module therefore
  does two things and nothing more:

    1. Defines a closed set of event names and a generic payload struct that
       carries only OAuth/OIDC vocabulary (subject, client id, scope, grant
       type, result, request metadata).
    2. Dispatches each event to the host's optional `:on_event` callback read
       from `AttestoPhoenix.Config`. When the callback is unset the dispatch is
       a no-op: the library emits, the host stores.

  The dispatcher never raises on a missing callback (emission is optional),
  never inspects or persists the event itself, and discards the callback's
  return value so a storage decision can never alter the authorization-server
  control flow that emitted the event.

  ## Configuration

  The callback is the `:on_event` field of `AttestoPhoenix.Config`. It accepts
  any of the `t:AttestoPhoenix.Config.callback/0` forms - an anonymous
  function, a `{module, function}` pair, or a full `{module, function, args}`
  tuple - and is invoked with the `%AttestoPhoenix.Event{}` struct. For the
  `{module, function, args}` form the event is prepended to `args`:

      config :my_app, AttestoPhoenix,
        on_event: &MyApp.OAuth.handle_event/1

      config :my_app, AttestoPhoenix,
        on_event: {MyApp.OAuth, :handle_event}

      config :my_app, AttestoPhoenix,
        on_event: {MyApp.OAuth, :handle_event, [extra_context]}
  """

  alias AttestoPhoenix.Config

  @typedoc """
  The closed set of authorization-server lifecycle events.

  * `:token_issued` - an access (and optionally refresh) token was issued in
    response to a successful grant (RFC 6749 §5.1).
  * `:token_denied` - a token request was rejected (RFC 6749 §5.2).
  * `:code_issued` - an authorization code was issued at the authorization
    endpoint in response to a successful authorization request (RFC 6749
    §4.1.2).
  * `:authorization_denied` - the resource owner refused an authorization
    request, reported to the client as `access_denied` (RFC 6749 §4.1.2.1).
  * `:authorization_failed` - an authorization request was rejected before a
    code was issued (RFC 6749 §4.1.2.1), whether reported as a direct error
    page or by redirect.
  * `:token_revoked` - a previously issued token was revoked (RFC 7009).
  * `:refresh_issued` - an initial refresh token was issued alongside an
    access token at the token endpoint (RFC 6749 §5.1, §6). Distinct from
    `:refresh_rotated`: no predecessor was consumed, this is the first token
    in a new rotation family.
  * `:refresh_rotated` - a refresh token was exchanged and a new refresh token
    issued, invalidating the presented one (RFC 6749 §6, RFC 6819 §5.2.2.3).
  * `:refresh_reuse_detected` - an already-rotated refresh token was presented
    again, indicating possible theft (RFC 6819 §5.2.2.3).
  * `:auth_succeeded` - a presented access token authenticated a protected
    resource request (RFC 6750 §2.1).
  * `:auth_denied` - a protected resource request was rejected (RFC 6750 §3.1).
  * `:client_registered` - a client was registered (RFC 7591).
  """
  @type name ::
          :token_issued
          | :token_denied
          | :code_issued
          | :authorization_denied
          | :authorization_failed
          | :token_revoked
          | :refresh_issued
          | :refresh_rotated
          | :refresh_reuse_detected
          | :auth_succeeded
          | :auth_denied
          | :client_registered

  # The closed set of recognized event names. Used to fail closed on an
  # unrecognized name rather than emitting an event the host cannot interpret.
  @names ~w(
    token_issued
    token_denied
    code_issued
    authorization_denied
    authorization_failed
    token_revoked
    refresh_issued
    refresh_rotated
    refresh_reuse_detected
    auth_succeeded
    auth_denied
    client_registered
  )a

  @typedoc """
  A neutral authorization-server event.

  Every field is optional because the populated subset depends on the event:
  a `:token_denied` before client authentication has no `:subject`, a
  `client_credentials` grant has no resource-owner `:subject`, and so on. The
  library never fabricates a value it does not have.

  * `:name` - the event name (one of `t:name/0`).
  * `:subject` - the resource owner identifier, the `sub` claim (RFC 7519
    §4.1.2) when one is present.
  * `:client_id` - the OAuth client identifier (RFC 6749 §2.2).
  * `:scope` - the granted or requested scope (RFC 6749 §3.3).
  * `:grant_type` - the grant type of the request (RFC 6749 §1.3).
  * `:result` - for denial events, a machine-readable reason term (typically an
    RFC 6749 §5.2 error code such as `:invalid_client` or `:invalid_grant`).
  * `:metadata` - a host-opaque map of request metadata (for example
    client IP or request identifiers). The library does not interpret this
    field; it is a pass-through for the caller.
  """
  @type t :: %__MODULE__{
          name: name(),
          subject: String.t() | nil,
          client_id: String.t() | nil,
          scope: String.t() | nil,
          grant_type: String.t() | nil,
          result: term() | nil,
          metadata: map()
        }

  @enforce_keys [:name]
  defstruct name: nil,
            subject: nil,
            client_id: nil,
            scope: nil,
            grant_type: nil,
            result: nil,
            metadata: %{}

  @doc """
  Builds an event struct for `name` from a payload of OAuth/OIDC fields.

  `name` must be a recognized event name (`t:name/0`); an unrecognized name
  raises `ArgumentError` so a typo fails closed instead of silently emitting an
  uninterpretable event. `fields` is a map or keyword list whose recognized
  keys (`:subject`, `:client_id`, `:scope`, `:grant_type`, `:result`,
  `:metadata`) populate the struct. An unknown key raises `KeyError` via
  `struct!/2` rather than being silently dropped.

  ## Examples

      iex> AttestoPhoenix.Event.new(:token_issued, client_id: "abc", scope: "openid")
      %AttestoPhoenix.Event{
        name: :token_issued,
        client_id: "abc",
        scope: "openid",
        metadata: %{}
      }
  """
  @spec new(name(), map() | keyword()) :: t()
  def new(name, fields \\ %{})

  def new(name, fields) when name in @names do
    struct!(__MODULE__, Map.put(Map.new(fields), :name, name))
  end

  def new(name, _fields) do
    raise ArgumentError,
          "unrecognized AttestoPhoenix event name: #{inspect(name)}. " <>
            "Recognized names: #{inspect(@names)}"
  end

  @doc """
  Emits an event to the host's `:on_event` callback, if one is configured.

  `config` is the `AttestoPhoenix.Config` for the request; the callback is read
  from its `:on_event` field. `name` plus `fields` are passed to `new/2` (so an
  unrecognized name raises). When `:on_event` is unset this is a no-op that
  returns `:ok`.

  Emission is observational: the callback's return value is discarded and `:ok`
  is always returned, so a host's storage decision can never alter the
  authorization-server control flow that emitted the event.
  """
  @spec emit(Config.t(), name(), map() | keyword()) :: :ok
  def emit(%Config{} = config, name, fields \\ %{}) when is_atom(name) do
    dispatch(Config.on_event_fun(config), new(name, fields))
  end

  @doc """
  Dispatches a pre-built event struct to a resolved `:on_event` callback.

  `callback` is any `t:AttestoPhoenix.Config.callback/0` form, or `nil` for the
  unconfigured case (a no-op returning `:ok`). Exposed for callers that already
  hold a built struct and the resolved callback.
  """
  @spec dispatch(Config.callback() | nil, t()) :: :ok
  def dispatch(nil, %__MODULE__{}), do: :ok

  def dispatch(callback, %__MODULE__{} = event) when is_function(callback, 1) do
    _ = callback.(event)
    :ok
  end

  def dispatch({module, function}, %__MODULE__{} = event) when is_atom(module) and is_atom(function) do
    _ = apply(module, function, [event])
    :ok
  end

  def dispatch({module, function, args}, %__MODULE__{} = event)
      when is_atom(module) and is_atom(function) and is_list(args) do
    _ = apply(module, function, [event | args])
    :ok
  end

  @doc """
  Returns the closed set of recognized event names.
  """
  @spec names() :: [name(), ...]
  def names, do: @names
end
