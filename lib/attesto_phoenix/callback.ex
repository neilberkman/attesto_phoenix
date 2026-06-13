defmodule AttestoPhoenix.Callback do
  @moduledoc """
  Invocation of configured callbacks in the forms accepted throughout the
  library.

  A callback supplied to `AttestoPhoenix.Config` (and to the plugs and
  controllers built on it) may be expressed as a bare anonymous/captured
  function, a `{module, function}` pair, or a `{module, function, extra_args}`
  tuple whose trailing arguments follow the per-call arguments. This module is
  the single place that resolves those forms; it carries no policy of its own.
  """

  @type callback :: function() | {module(), atom()} | {module(), atom(), [any()]}

  @doc """
  Invoke `callback` with `args`.

  For the `{module, function, extra_args}` form the `extra_args` are appended
  after `args`, matching `AttestoPhoenix.Config`'s `callback` type.
  """
  @spec invoke(callback(), [any()]) :: any()
  def invoke(fun, args) when is_function(fun) and is_list(args), do: apply(fun, args)

  def invoke({module, fun}, args) when is_atom(module) and is_atom(fun) and is_list(args), do: apply(module, fun, args)

  def invoke({module, fun, extra}, args) when is_atom(module) and is_atom(fun) and is_list(extra) and is_list(args),
    do: apply(module, fun, args ++ extra)

  @doc """
  Invoke `callback` with `args`, returning `default` when `callback` is `nil`.
  """
  @spec invoke(callback() | nil, [any()], any()) :: any()
  def invoke(nil, _args, default), do: default
  def invoke(callback, args, _default), do: invoke(callback, args)

  @doc """
  Read a configured callback off the config struct by `key`.

  This is the single reader the controllers, plugs, and core modules share for
  pulling a host callback out of `%AttestoPhoenix.Config{}` (or any struct/map
  carrying it). An absent key reads as `nil`, matching the fail-closed
  resolution used throughout the library; the value is otherwise returned
  unchanged for an `invoke/2,3` caller to run. It carries no policy.
  """
  @spec config_callback(map(), atom()) :: callback() | nil
  def config_callback(config, key) when is_map(config) and is_atom(key), do: Map.get(config, key)

  @doc """
  Read a boolean policy flag off the config struct by `key`.

  An absent or non-boolean value reads as `false` (fail closed: a flag the host
  did not set never turns a control on).
  """
  @spec config_flag(map(), atom()) :: boolean()
  def config_flag(config, key) when is_map(config) and is_atom(key), do: Map.get(config, key) == true
end
