defmodule AttestoPhoenix.Router do
  @moduledoc """
  Router macro that mounts the authorization-server endpoints.

  `use AttestoPhoenix.Router` makes the `attesto_routes/1` macro available
  inside a `Phoenix.Router`. Calling it inside (or alongside) a `scope`
  declares the OAuth 2.0 / OpenID Connect server surface:

    * `GET /.well-known/oauth-authorization-server` - authorization-server
      metadata (RFC 8414 §3).
    * `GET /.well-known/openid-configuration` - OpenID Provider configuration
      (OpenID Connect Discovery 1.0 §4).
    * `GET /.well-known/jwks.json` - the JSON Web Key Set of the verification
      keys (RFC 7517 §5; the discovery document's `jwks_uri` per RFC 8414 §2).
    * `GET /oauth/authorize` - the authorization endpoint (RFC 6749 §3.1;
      OpenID Connect Core 1.0 §3.1.2).
    * `POST /oauth/token` - the token endpoint (RFC 6749 §3.2).
    * `POST /oauth/par` - pushed authorization requests (RFC 9126).
    * `POST /oauth/revoke` - the token revocation endpoint (RFC 7009 §2).
    * `POST /oauth/introspect` - the token introspection endpoint (RFC 7662 §2),
      with the RFC 9701 signed-JWT response negotiated by the `Accept` header.
    * `POST /oauth/register` - dynamic client registration (RFC 7591 §3.1),
      mounted only when registration is enabled (see `:registration` below).
    * `DELETE /oauth/register/:client_id` - dynamic client registration
      management cleanup (RFC 7592 §2), mounted with registration.
    * `GET` and `POST /oauth/userinfo` - the UserInfo endpoint (OpenID Connect
      Core 1.0 §5.3); a bearer-authenticated protected resource (RFC 6750 §2.1).

  The macro emits nothing but `Phoenix.Router` route entries pointing at this
  library's controllers; it holds no policy of its own. Every behavioral
  decision (which clients exist, which scopes are granted, whether DPoP / mTLS
  binding is offered, whether registration is open) is owned by the host
  through `AttestoPhoenix.Config`, which the controllers read at request time.

  ## Placement and pipelines

  The discovery, OpenID configuration, and JWKS documents are unauthenticated
  public metadata (RFC 8414 §5; OpenID Connect Discovery 1.0 §4; RFC 8615).
  The authorization endpoint does not authenticate the client (RFC 6749 §3.1):
  the resource owner authenticates through the host's login/consent callbacks,
  so it carries no client-authentication pipeline. The token, revocation, and
  registration endpoints authenticate the client from the request itself
  (RFC 6749 §2.3, RFC 7009 §2, RFC 7591 §3), and the UserInfo endpoint is
  bearer-authenticated from the `Authorization` header (RFC 6750 §2.1) by its
  controller, rather than from a caller session, so they too take no
  session-bearing pipeline. Supply a `:pipeline` only to attach
  transport-level concerns the host wants in front of every endpoint (for
  example a parser that accepts `application/x-www-form-urlencoded` at the
  token endpoint per RFC 6749 §4.4.2, or an HTTPS-enforcing plug).

      scope "/" do
        attesto_routes()
      end

      # or with a host pipeline and a mount prefix:
      scope "/" do
        attesto_routes(pipeline: :oauth_server, prefix: "/auth")
      end

  ## Options

    * `:prefix` - path segment prepended to the `/oauth/*` endpoints (the
      well-known documents always live at the host root per RFC 8615, so the
      prefix does not apply to them). Defaults to `""`.
    * `:pipeline` - a pipeline name (atom) or list of pipeline names to
      `pipe_through` for the mounted routes. Defaults to `[]` (no extra
      pipeline; the surrounding `scope`'s `pipe_through`, if any, still
      applies).
    * `:registration` - when `true`, mounts `POST /oauth/register`
      (RFC 7591) and `DELETE /oauth/register/:client_id` (RFC 7592). Defaults
      to `false`. The endpoints still fail closed at request time unless the
      host has wired the registration callbacks in `AttestoPhoenix.Config`;
      this option only controls whether the routes exist, so a deployment that
      never offers registration presents no registration surface at all.

  The library never inspects `:registration` to make a policy decision: it is
  a route-existence toggle. Authorization-server metadata advertised at the
  discovery endpoint is derived from `AttestoPhoenix.Config` by the discovery
  controller, not from these macro options.
  """

  # Well-known paths are fixed by their registries and are NOT subject to the
  # host's `:prefix`. RFC 8414 §3 pins authorization-server metadata to the
  # `/.well-known/oauth-authorization-server` URI, and RFC 8615 reserves the
  # `/.well-known/` path segment at the host root. RFC 7517 §5 defines the JWK
  # Set document the metadata's `jwks_uri` points at.
  @discovery_path "/.well-known/oauth-authorization-server"
  @jwks_path "/.well-known/jwks.json"

  # OpenID Connect Discovery 1.0 §4 pins the OpenID Provider configuration
  # document to the `/.well-known/openid-configuration` URI, also anchored at
  # the host root under RFC 8615 and therefore NOT subject to the `:prefix`.
  @openid_configuration_path "/.well-known/openid-configuration"

  # The OAuth endpoints live under the host-chosen `:prefix`. These are the
  # path tails appended to it. They derive from the SAME tail constants
  # `AttestoPhoenix.Config` resolves its advertised endpoint URLs from, joined
  # onto the default OAuth prefix (`"/oauth"`), so the routes this macro mounts
  # and the routes the discovery documents advertise cannot drift: a host that
  # mounts at `/oauth/*` (the default) and configures the matching default
  # `:oauth_path_prefix` advertises exactly the paths mounted here.
  @oauth_prefix "/oauth"
  @authorize_path @oauth_prefix <> AttestoPhoenix.Config.authorize_tail()
  @token_path @oauth_prefix <> AttestoPhoenix.Config.token_tail()
  @par_path @oauth_prefix <> AttestoPhoenix.Config.par_tail()
  @revoke_path @oauth_prefix <> AttestoPhoenix.Config.revocation_tail()
  @introspect_path @oauth_prefix <> AttestoPhoenix.Config.introspection_tail()
  @register_path @oauth_prefix <> AttestoPhoenix.Config.registration_tail()
  @userinfo_path @oauth_prefix <> AttestoPhoenix.Config.userinfo_tail()

  # Controllers that back each endpoint. Named here once so the macro
  # expansion does not scatter controller module references through the
  # callers' router source.
  @discovery_controller AttestoPhoenix.Controller.DiscoveryController
  @openid_configuration_controller AttestoPhoenix.Controller.OpenIDConfigurationController
  @jwks_controller AttestoPhoenix.Controller.JWKSController
  @authorize_controller AttestoPhoenix.Controller.AuthorizeController
  @token_controller AttestoPhoenix.Controller.TokenController
  @par_controller AttestoPhoenix.Controller.PARController
  @revocation_controller AttestoPhoenix.Controller.RevocationController
  @introspection_controller AttestoPhoenix.Controller.IntrospectionController
  @registration_controller AttestoPhoenix.Controller.RegistrationController
  @userinfo_controller AttestoPhoenix.Controller.UserinfoController

  @doc false
  defmacro __using__(_opts) do
    quote do
      import AttestoPhoenix.Router, only: [attesto_routes: 0, attesto_routes: 1]
    end
  end

  @doc """
  Mounts the authorization-server endpoints. See the module documentation for
  the route table and the accepted options.
  """
  defmacro attesto_routes(opts \\ []) do
    prefix = Keyword.get(opts, :prefix, "")
    pipelines = opts |> Keyword.get(:pipeline, []) |> List.wrap()
    registration? = Keyword.get(opts, :registration, false)

    discovery_path = @discovery_path
    openid_configuration_path = @openid_configuration_path
    jwks_path = @jwks_path
    authorize_path = @authorize_path
    token_path = @token_path
    par_path = @par_path
    revoke_path = @revoke_path
    introspect_path = @introspect_path
    register_path = @register_path
    userinfo_path = @userinfo_path
    discovery_controller = @discovery_controller
    openid_configuration_controller = @openid_configuration_controller
    jwks_controller = @jwks_controller
    authorize_controller = @authorize_controller
    token_controller = @token_controller
    par_controller = @par_controller
    revocation_controller = @revocation_controller
    introspection_controller = @introspection_controller
    registration_controller = @registration_controller
    userinfo_controller = @userinfo_controller

    # `pipe_through/1` is a compile-time `Phoenix.Router` macro: it must be
    # expanded once per pipeline as it is written into the scope, not iterated
    # at runtime. Unroll the requested pipelines into individual quoted calls
    # at macro-expansion time (an empty list yields no calls, piping through
    # nothing extra) so a host that wires a parser / HTTPS pipeline attaches it
    # to this server scope only, never leaking onto unrelated routes.
    pipe_through_calls =
      for attesto_pipeline <- pipelines do
        quote do
          pipe_through(unquote(attesto_pipeline))
        end
      end

    # The registration routes are emitted only when the host opts in (RFC 7591
    # §3.1 / RFC 7592 §2), decided here at expansion time so a deployment that
    # never registers clients exposes no registration endpoint at all.
    registration_route =
      if registration? do
        quote do
          post(
            unquote(prefix <> register_path),
            unquote(registration_controller),
            :create
          )

          delete(
            unquote(prefix <> register_path <> "/:client_id"),
            unquote(registration_controller),
            :delete
          )
        end
      end

    quote do
      scope "/" do
        unquote_splicing(pipe_through_calls)

        # RFC 8615: the well-known documents are anchored at the host root and
        # are not relocated by the host's `:prefix`. RFC 8414 §3 (OAuth
        # authorization-server metadata) and OpenID Connect Discovery 1.0 §4
        # (OpenID Provider configuration) are both unauthenticated public
        # metadata served at their registered URIs.
        get(unquote(discovery_path), unquote(discovery_controller), :show)
        get(unquote(openid_configuration_path), unquote(openid_configuration_controller), :show)
        get(unquote(jwks_path), unquote(jwks_controller), :show)

        # RFC 6749 §3.1 / OpenID Connect Core 1.0 §3.1.2: the authorization
        # endpoint accepts both GET and POST under the host-chosen prefix. It
        # carries no client-authentication pipeline (RFC 6749 §3.1: the client
        # is not authenticated here; the resource owner authenticates through
        # the host's login/consent callbacks).
        get(unquote(prefix <> authorize_path), unquote(authorize_controller), :authorize)
        post(unquote(prefix <> authorize_path), unquote(authorize_controller), :authorize)

        # RFC 6749 §3.2 / RFC 7009 §2: token issuance and revocation are POST
        # endpoints under the host-chosen prefix. They authenticate the client
        # from the request itself (RFC 6749 §2.3, RFC 7009 §2).
        post(unquote(prefix <> token_path), unquote(token_controller), :create)
        post(unquote(prefix <> par_path), unquote(par_controller), :create)
        post(unquote(prefix <> revoke_path), unquote(revocation_controller), :create)

        # RFC 7662 §2: token introspection is a POST endpoint that authenticates
        # the client from the request (RFC 7662 §2.1); RFC 9701 adds the signed
        # JWT response negotiated by the Accept header.
        post(unquote(prefix <> introspect_path), unquote(introspection_controller), :create)

        unquote(registration_route)

        # OpenID Connect Core 1.0 §5.3.1: the UserInfo endpoint accepts both
        # GET and POST, and is a bearer-authenticated protected resource
        # (RFC 6750 §2.1). The controller verifies the presented access token
        # from the `Authorization` header before returning any claim, so the
        # endpoint authenticates from the request itself rather than from a
        # caller session.
        get(unquote(prefix <> userinfo_path), unquote(userinfo_controller), :userinfo)
        post(unquote(prefix <> userinfo_path), unquote(userinfo_controller), :userinfo)
      end
    end
  end
end
