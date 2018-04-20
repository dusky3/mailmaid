require Logger

defmodule Mailmaid.SMTP.Client.Connection do
  import Mailmaid.SMTP.Client.Commands, only: [read_possible_multiline_reply: 1]

  def open(hostname, options) do
    options = Enum.into(options, %{})
    hostname = String.to_charlist(hostname)

    additional_socket_options = cond do
      Map.has_key?(options, :sockopts) ->
        Logger.warn "sockopts is deprecated, use socket_options instead"
        options[:sockopts]
      Map.has_key?(options, :socket_options) -> options[:socket_options]
      true -> []
    end

    socket_options = [
      :binary,
      {:packet, :line},
      {:keepalive, true},
      {:active, false}
      | additional_socket_options
    ]

    protocol = cond do
      Map.has_key?(options, :protocol) ->
        #Logger.debug ["explicit protocol given ", inspect(options[:protocol])]
        options[:protocol]

      Map.has_key?(options, :ssl) ->
        Logger.warn "ssl option is deprecated, use `protocol: :ssl` instead"
        if options[:ssl] do
          :ssl
        else
          :tcp
        end

      true -> :tcp
    end

    port = case options[:port] do
      nil ->
        case protocol do
          :ssl -> 465
          :tcp -> 25
        end
      p when is_integer(p) -> p
    end

    connect_timeout = options[:connect_timeout] || 5000

    case :socket.connect(protocol, hostname, port, socket_options, connect_timeout) do
      {:ok, socket} ->
        #IO.inspect socket
        #Logger.debug ["Connected successfully, waiting for banner protocol=", inspect(protocol)]
        case read_possible_multiline_reply(socket) do
          {:ok, socket, ["220" <> _banner | _rest] = messages} ->
            {:ok, socket, {protocol, hostname, port}, messages}
          {:ok, socket, ["4" <> _other | _rest] = messages} -> {:error,
            {:temporary_failure, socket, messages}}
          {:ok, socket, messages} ->
            {:error, {:permanent_failure, socket, messages}}
          {:error, _} = err -> err
        end
      {:error, reason} ->
        {:error, {:network_failure, reason}}
    end
  end

  def close(socket) do
    :socket.close(socket)
    :ok
  end
end
