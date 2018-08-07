require Logger

defmodule Mailmaid.SMTP.Server do
  defmacro __using__(_opts) do
    quote do
      @behaviour Mailmaid.SMTP.Protocol
    end
  end

  @moduledoc """
  Wrapper around Ranch to make it friendly with
  """
  alias :ranch, as: Ranch

  @type ubyte_t :: {0..255}
  @type int16_t :: {0..0xFFFF}
  @type ipv4_t :: {ubyte_t, ubyte_t, ubyte_t, ubyte_t}
  @type ipv6_t :: {int16_t, int16_t, int16_t, int16_t, int16_t, int16_t}
  @type listener_config :: [
    {:address, ipv4_t | ipv6_t},
    {:family, :inet | :inet6},
    {:hostname, String.t},
    {:num_acceptors, non_neg_integer},
    {:port, non_neg_integer},
    {:sessionoptions, Keyword.t},
    {:protocol, :tcp | :ssl},
    {:ssl_options, [
      {:keyfile, String.t},
      {:certfile, String.t},
    ]},
  ]
  @type process_options :: [
    {:name, atom},
  ]

  def child_spec(options) do
    %{
      id: options[:id] || options[:session_module],
      start: {
        __MODULE__,
        :start_link,
        [
          options[:session_module],
          options[:listeners],
          Keyword.get(options, :process_options, []),
        ]
      },
      restart: :permanent,
      type: :worker,
      shutdown: 10_000
    }
  end

  @doc """
  Starts a new SMTP server listener

  Args:
  * `session_module` - the callback module and name of the listener
  * `listeners` - a list of keyword lists. For now just wrap the args in a list.
  """
  @spec start_link(session_module :: atom, listeners :: [listener_config], process_options) :: {:ok, pid} | {:error, term}
  def start_link(session_module, listeners, process_options \\ []) do
    GenServer.start_link(__MODULE__, {session_module, listeners}, process_options)
  end

  def init({session_module, listeners}) do
    Process.flag(:trap_exit, true)
    state = %{
      session_module: session_module,
      listeners: %{}
    }

    listeners
    |> Enum.reduce({:ok, state}, fn
      listener, {:ok, acc} ->
        case do_start_listener(listener, acc) do
          {:ok, _, acc2} -> {:ok, acc2}
          {:error, reason} -> {:error, acc, reason}
        end
      _, {:error, _acc, _reason} = err -> err
    end)
    |> case do
      {:ok, _state} = res ->
        res
      {:error, state, reason} ->
        terminate(reason, state)
        {:stop, reason}
    end
  end

  def terminate(reason, %{listeners: listeners} = state) do
    Logger.warn [
      "#{__MODULE__}: terminating",
      " session_module=#{inspect state.session_module}",
      " reason=#{inspect reason}",
    ]
    Enum.each(listeners, fn {_monitor_ref, {_monitor_ref2, ref, _pid, _listener_options}} ->
      case Ranch.stop_listener(ref) do
        :ok ->
          Logger.debug [
            "#{__MODULE__}: stopped listener",
            " ref=#{inspect ref}"
          ]
        {:error, :not_found} ->
          Logger.warn [
            "#{__MODULE__}: listener was not found",
            " ref=#{inspect ref}"
          ]
     end
    end)
    Logger.debug "#{__MODULE__}: stopped listeners"
    :ok
  end

  defp do_start_listener_process(listener_options, state) do
    ref = listener_options[:ref] || make_ref()
    num_acceptors = Keyword.get(listener_options, :num_acceptors, 256)
    transport_opts = [
      {:port, Keyword.get(listener_options, :port, 2525)},
      Keyword.get(listener_options, :family, :inet)
    ]
    opts = [
      session_module: state.session_module,
      hostname: Keyword.get(listener_options, :hostname) || to_string(:smtp_util.guess_FQDN()),
      address: Keyword.get(listener_options, :address) || {0, 0, 0, 0},
      session_options: Keyword.get(listener_options, :sessionoptions, []),
      tls: false,
      ssl_options: Keyword.get(listener_options, :ssl_options, []),
    ]
    {transport, transport_opts, opts} = case Keyword.get(listener_options, :protocol, :tcp) do
      :tcp -> {:ranch_tcp, transport_opts, opts}
      :ssl ->
        more_options = Keyword.get(listener_options, :ssl_options)
        {:ranch_ssl, transport_opts ++ more_options, Keyword.put(opts, :tls, true)}
    end
    case Ranch.start_listener(ref, num_acceptors, transport, transport_opts, Mailmaid.SMTP.Protocol, opts) do
      {:ok, pid} ->
        mon_ref = Process.monitor(pid)
        Logger.debug [
          "#{__MODULE__}:",
          " started listener",
          " session_module=", inspect(state.session_module),
          " ref=", inspect(ref),
          " pid=", inspect(pid),
          " transport=", inspect(transport),
          " port=", inspect(transport_opts[:port]),
          " hostname=", inspect(opts[:hostname]),
          " address=", inspect(opts[:address]),
        ]
        {:ok, {mon_ref, ref, pid, listener_options}}
      {:error, _} = err -> err
    end
  end

  def do_start_listener(listener_options, state) do
    case do_start_listener_process(listener_options, state) do
      {:ok, {monitor_ref, _ref, _pid, _listener_options} = res} ->
        listeners = Map.put(state.listeners, monitor_ref, res)
        {:ok, monitor_ref, %{state | listeners: listeners}}
      {:error, reason} ->
        {:error, {:start_error, reason}}
    end
  end

  defp do_remove_listener(monitor_ref, state) do
    listeners = Map.delete(state.listeners, monitor_ref)
    %{state | listeners: listeners}
  end

  defp do_stop_listener(monitor_ref, state) do
    case state.listeners[monitor_ref] do
      nil -> state
      {^monitor_ref, ref, _pid} ->
        Ranch.stop_listener(ref)
        do_remove_listener(monitor_ref, state)
    end
  end

  def handle_info({:DOWN, monitor_ref, :process, _object, reason}, state) do
    Logger.error "#{__MODULE__}: process is down ref=#{inspect monitor_ref} reason=#{inspect reason}"
    #state = do_remove_listener(monitor_ref, state)
    #{:noreply, state}
    {:stop, {:listener_down, monitor_ref, reason}, state}
  end

  def handle_cast({:start_listener, listener_options}, state) do
    case do_start_listener(listener_options, state) do
      {:ok, _ref, state} ->
        {:noreply, state}
      {:error, reason} ->
        {:stop, reason, state}
    end
  end

  def handle_cast({:stop_listener, monitor_ref}, state) do
    state = do_stop_listener(monitor_ref, state)
    {:noreply, state}
  end

  def stop(pid) do
    GenServer.stop(pid)
  end
end
