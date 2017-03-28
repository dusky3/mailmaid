require Logger

defmodule Mailmaid.SMTP.Server do
  defmodule Listener do
    defstruct hostname: nil, port: nil, sessionoptions: [], socket: nil, listenoptions: []

    @type t :: %__MODULE__{
      hostname: String.t,
      port: integer,
      sessionoptions: list,
      socket: port,
      listenoptions: list
    }
  end

  defmodule State do
    defstruct listeners: [], module: nil, sessions: []
  end

  use GenServer

  def handle_call(:stop, _from, state) do
    {:stop, :normal, :ok, state}
  end

  def handle_call(:sessions, _from, state) do
    {:reply, state.sessions, state}
  end

  def handle_call(request, _from, state) do
    {:reply, {:unknown_call, request}, state}
  end

  def handle_cast(_msg, state) do
    {:noreply, state}
  end

  def handle_info({:inet_async, listen_port, _, {:ok, client_accept_socket}}, %{module: module, listeners: listeners, sessions: cur_sessions} = state) do
    try do
      # find this listen_port in our listeners.
      listener =
        listeners
        |> Enum.find(&(&1.port == listen_port))

      {:ok, client_socket} = :socket.handle_inet_async(listener.socket, client_accept_socket, listener.listenoptions)

      # New client connected
      # io:format("new client connection.~n", [])
      session_options = [{:hostname, listener.hostname}, {:sessioncount, length(cur_sessions) + 1} | listener.sessionoptions]
      sessions = case Mailmaid.SMTP.Server.Session.start(client_socket, module, session_options) do
        {:ok, pid} ->
          Process.link(pid)
          :socket.controlling_process(client_socket, pid)
          cur_sessions ++ [pid]

        {:error, reason} ->
          :error_logger.error_msg("Error in session: ~p.~n", [reason])
          cur_sessions
      end

      {:noreply, %State{state | sessions: sessions}}
    rescue
      error in Exception ->
        :error_logger.error_msg("Error in socket acceptor: ~p.~n", [error])
        {:noreply, state}
    end
  end

  def handle_info({:EXIT, from, reason}, state) do
    case Enum.member?(state.sessions, from) do
      true ->
        {:noreply, %State{state | sessions: List.delete(state.sessions, from)}}

      false ->
        :io.format("process ~p exited with reason ~p~n", [from, reason])
        {:noreply, state}
    end
  end

  def handle_info({:inet_async, listen_socket, _, {:error, :econnaborted}}, state) do
    :io.format("Client terminated connection with econnaborted~n")
    :socket.begin_inet_async(listen_socket)
    {:noreply, state}
  end

  def handle_info({:inet_async, _listen_socket,_, error}, state) do
    :error_logger.error_msg("Error in socket acceptor: ~p.~n", [state])
    {:stop, error, state}
  end

  def handle_info(_info, state) do
    {:noreply, state}
  end

  def sessions(pid) do
    GenServer.call(pid, :sessions)
  end

  @spec start_listener(base_config :: term, default_config :: term) :: Listener.t | {:error, reason :: term}
  def start_listener(base_config, default_config) do
    config = Keyword.merge(default_config, base_config)

    port = Keyword.get(config, :port)
    ip = Keyword.get(config, :address)
    family = Keyword.get(config, :family)
    hostname = Keyword.get(config, :domain)
    protocol = Keyword.get(config, :protocol)
    sessionoptions = Keyword.get(config, :sessionoptions, [])
    listenoptions = [:binary, {:ip, ip}, family]

    case :socket.listen(protocol, port, listenoptions) do
      # Create first accepting process
      {:ok, listen_socket} ->
        :error_logger.info_msg("~p listening on ~p:~p via ~p~n", [__MODULE__, ip, port, protocol])
        :socket.begin_inet_async(listen_socket)

        %Listener{
          port: :socket.extract_port_from_socket(listen_socket),
          hostname: hostname,
          sessionoptions: sessionoptions,
          socket: listen_socket,
          listenoptions: listenoptions
        }

      {:error, reason} = err ->
        :error_logger.error_msg("~p could not listen on ~p:~p via ~p. Error: ~p~n", [__MODULE__, ip, port, protocol, reason])
        err
    end
  end

  def init([module, options]) do
    :erlang.process_flag(:trap_exit, true)

    Logger.info "#{__MODULE__} starting at #{node()}"

    default_config = [
      domain: :smtp_util.guess_FQDN(),
      address: {0,0,0,0},
      port: 2525,
      protocol: :tcp,
      family: :inet
    ]

    listeners = Enum.map(options, &(start_listener(&1, default_config)))

    case Enum.drop_while(listeners, fn
      %Listener{} -> true
      {:error, _} -> false
    end) do
      [] ->
        {:ok, %State{
          module: module,
          listeners: listeners
        }}

      _ ->
        {:error, {:init, :erlang.hd(listeners)}}
    end
  end

  def terminate(reason, state) do
    :io.format("Terminating due to ~p~n", [reason])

    Enum.each(state.listeners, fn %{socket: s} ->
      try do
        :socket.close(s)
      catch err ->
        {:error, err}
      end
    end)

    :ok
  end

  def start(module, listeners, gen_server_config \\ []) do
    GenServer.start(__MODULE__, [module, listeners], gen_server_config)
  end

  def start_link(module, listeners, gen_server_config \\ []) do
    GenServer.start_link(__MODULE__, [module, listeners], gen_server_config)
  end
end
