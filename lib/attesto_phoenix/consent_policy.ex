defmodule AttestoPhoenix.ConsentPolicy do
  @moduledoc """
  The host-owned resource-owner authentication and consent contract
  (RFC 6749 §3.1 / §4.1.1, OpenID Connect Core §3.1.2).

  The authorization endpoint runs the host's login and consent UI, so the
  library mounts the endpoint but delegates the resource-owner interaction to
  the host. A host implements this behaviour and wires each callback into
  `AttestoPhoenix.Config`; this module is the contract those keys install and
  the recommended production shape.

  Each `@callback` corresponds to the identically named `AttestoPhoenix.Config`
  key:

    * `authenticate_resource_owner/3` (`:authenticate_resource_owner`)
    * `consent/3` (`:consent`)
  """

  @doc """
  Establish the resource owner for an authorization request (RFC 6749 §3.1,
  OpenID Connect Core §3.1.2.3).

  Returns `{:authenticated, subject}` once a resource owner is known (a map
  carrying at least `:subject`, the OIDC `sub`, and optionally `:auth_time`,
  `:acr`, `:amr`); `{:halt, conn}` to take over the connection (e.g. redirect
  to a host login page that re-enters the authorization endpoint); `{:none}`
  when no subject can be established without UI; or an `{:error, _}`
  classifying why interaction is required (OpenID Connect Core §3.1.2.6).

  `auth_opts` carries the OpenID Connect Core §3.1.2.1 `prompt`/`max_age`
  directives the host must honour (`:prompt`, `:force_reauth`, `:interactive`,
  `:max_age`).
  """
  @callback authenticate_resource_owner(
              conn :: Plug.Conn.t(),
              request :: term(),
              auth_opts :: map()
            ) ::
              {:authenticated, map()}
              | {:halt, Plug.Conn.t()}
              | {:none}
              | {:error, :login_required | :consent_required | :interaction_required}

  @doc """
  Obtain the resource owner's consent for an authorization request
  (RFC 6749 §4.1.1).

  Returns `{:consented, subject}` to proceed (the returned subject may carry
  consent-derived claims), `{:halt, conn}` to take over the connection (e.g.
  render a consent screen that re-enters the authorization endpoint), or
  `{:denied, reason}` to refuse (reported to the client as `access_denied`,
  RFC 6749 §4.1.2.1). When the Config key is unset, consent is implicitly
  granted for the authenticated subject.
  """
  @callback consent(conn :: Plug.Conn.t(), request :: term(), subject :: map()) ::
              {:consented, map()} | {:halt, Plug.Conn.t()} | {:denied, term()}

  @optional_callbacks authenticate_resource_owner: 3, consent: 3
end
