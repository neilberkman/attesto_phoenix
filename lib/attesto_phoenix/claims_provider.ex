defmodule AttestoPhoenix.ClaimsProvider do
  @moduledoc """
  The host-owned UserInfo claim source (OpenID Connect Core §5).

  The library knows no user store: the identity claims the UserInfo endpoint
  (OpenID Connect Core §5.3) returns are the host's to source. This behaviour is
  the home for that single concern — sourcing claim *values* for a subject. It
  deliberately does NOT own principal loading: building the principal an
  authorization-code grant mints a token for is a separate responsibility that
  lives on `AttestoPhoenix.PrincipalStore` (`build_principal/3`). Keeping claim
  sourcing and principal loading in distinct behaviours means a host installs
  each capability where it belongs rather than behind one overloaded module.

  A host implements this behaviour and wires its callback into
  `AttestoPhoenix.Config` under `:claims_provider` (or passes the flat
  `:build_userinfo_claims` callback). Wiring is unchanged from passing the
  callback individually (an anonymous function, a `{module, function}` pair, or
  a `{module, function, extra_args}` triple).

  Each `@callback` corresponds to the identically named `AttestoPhoenix.Config`
  key:

    * `build_userinfo_claims/3` (`:build_userinfo_claims`) - the UserInfo source.
    * `build_id_token_claims/4` (`:build_id_token_claims`) - the ID Token source.

  These are deliberately separate callbacks, not one overloaded function: the
  UserInfo endpoint and the ID Token draw from different `claims`-parameter
  members and treat `sub` differently, so a host implements whichever surface(s)
  it serves.
  """

  @typedoc "The host's opaque client representation (e.g. an Ecto struct)."
  @type client :: term()

  @doc """
  Produce the claim values the UserInfo endpoint (OpenID Connect Core §5.3)
  returns for the authenticated subject.

  Receives the subject identifier (`sub`), the list of scopes on the access
  token, and the per-claim request map from the OpenID Connect `claims`
  parameter (`%{}` when none). The host owns the claim source; the library owns
  the scope-to-claim shaping (OpenID Connect Core §5.4) and forces `sub` to the
  verified token subject (OpenID Connect Core §5.3.2). Returns a map of claim
  values.
  """
  @callback build_userinfo_claims(
              subject :: String.t(),
              granted_scopes :: [String.t()],
              requested_claims :: map()
            ) :: map()

  @doc """
  Produce the host claims merged into an ID Token (OpenID Connect Core §3.1.3.6
  / §5.5 `id_token` member).

  Receives the resolved `client`, the subject identifier, the granted scopes,
  and the per-claim request map. Distinct from `build_userinfo_claims/3`: it
  draws from the `claims` parameter's `id_token` member and MUST NOT carry `sub`
  (the library sets the verified subject; a host-supplied `sub` is rejected by
  `Attesto.IDToken`). Returns a map of claim values.
  """
  @callback build_id_token_claims(
              client(),
              subject :: String.t(),
              granted_scopes :: [String.t()],
              requested_claims :: map()
            ) :: map()

  # Both optional on the behaviour: a host installs `:claims_provider` and
  # implements whichever surface(s) it serves; an omitted callback resolves to
  # nil and that claim source fails closed at use, matching the boot-validation
  # policy (`claims_provider` has no required callbacks).
  @optional_callbacks build_userinfo_claims: 3, build_id_token_claims: 4
end
