defmodule AttestoPhoenix.PrincipalStore do
  @moduledoc """
  The host-owned subject/principal contract.

  The library resolves the subject during protected-resource authentication
  and builds the principal map minted into issued tokens, but the subject
  source (the host's user store) and the claim shaping are host policy. A host
  implements this behaviour and wires each callback into
  `AttestoPhoenix.Config`; this module is the contract those keys install and
  the recommended production shape.

  Each `@callback` corresponds to the identically named `AttestoPhoenix.Config`
  key:

    * `load_principal/1` (`:load_principal`, required)
    * `build_principal/3` (`:build_principal`)
  """

  @typedoc "The host's opaque principal/subject representation."
  @type principal :: term()

  @doc """
  Resolve the subject/principal by its identifier during protected-resource
  authentication. Returns `{:ok, principal}` or `{:error, :not_found}`.
  """
  @callback load_principal(subject_id :: String.t()) ::
              {:ok, principal()} | {:error, :not_found}

  @doc """
  Build the principal map passed to `Attesto.Token.mint/3` for an
  authorization-code grant. Receives the resolved client, the subject
  identifier, and the granted scope. The returned map carries at least
  `:subject` and any host-owned claims.
  """
  @callback build_principal(
              client :: term(),
              subject :: String.t(),
              scope :: [String.t()]
            ) :: map()

  @optional_callbacks build_principal: 3
end
