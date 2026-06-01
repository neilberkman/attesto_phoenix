defmodule AttestoPhoenix.EventSink do
  @moduledoc """
  The host-owned audit/telemetry contract.

  The library emits `%AttestoPhoenix.Event{}` structs at authorization-server
  milestones (token issuance, revocation, client registration, and so on) but
  never stores them itself. A host implements this behaviour and wires the
  callback into `AttestoPhoenix.Config` under `:on_event`; this module is the
  contract that key installs and the recommended production shape. When the key
  is unset, event emission is a no-op.
  """

  @doc """
  Handle an authorization-server event. The return value is ignored; the host
  owns persistence, metrics, and logging. The callback must not raise on the
  request path (a failing audit sink should degrade, not break token issuance).
  """
  @callback on_event(event :: AttestoPhoenix.Event.t()) :: any()
end
