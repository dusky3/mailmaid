require Logger

defmodule Mailmaid.SMTP.Client.Connection do
  import Mailmaid.SMTP.Client.Commands, only: [read_possible_multiline_reply: 1]

  defp process_options(options) do
    options = Enum.into(options, %{})
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

    options = Map.put(options, :socket_options, socket_options)

    protocol = cond do
      Map.has_key?(options, :protocol) ->
        Logger.debug ["explicit protocol given ", inspect(options[:protocol])]
        case options[:protocol] do
          p when p in [:ssl, :tcp] -> p
          p when p in ["ssl", "tcp"] ->
            Logger.warn "use atoms for protocols, not strings"
            String.to_existing_atom(p)
          _ ->
            raise ""
        end

      Map.has_key?(options, :ssl) ->
        Logger.warn "ssl option is deprecated, use `protocol: :ssl` instead"
        if options[:ssl] do
          :ssl
        else
          :tcp
        end

      true -> :tcp
    end

    options = Map.put(options, :protocol, protocol)

    port = case options[:port] do
      nil ->
        case protocol do
          :ssl -> 465
          :tcp -> 25
        end
      p when is_integer(p) -> p
    end
    options = Map.put(options, :port, port)

    Map.put(options, :connect_timeout, options[:connect_timeout] || 5000)
  end

  def open(hostname, options) do
    options = process_options(options)
    hostname = String.to_charlist(hostname)
    case :socket.connect(options.protocol, hostname, options.port, options.socket_options, options.connect_timeout) do
      {:ok, socket} ->
        Logger.debug ["Connected successfully, waiting for banner protocol=", inspect(options.protocol)]
        case read_possible_multiline_reply(socket) do
          {:ok, socket, ["220" <> _banner | _rest] = messages} ->
            Logger.debug ["Received banner messages=", inspect(messages)]
            {:ok, socket, options, messages}
          {:ok, socket, ["4" <> _other | _rest] = messages} -> {:error,
            {:temporary_failure, socket, messages}}
          {:ok, socket, messages} ->
            {:error, {:permanent_failure, socket, messages}}
          {:error, _socket, reason} -> {:error, reason}
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
