require Logger

defmodule Mailmaid.SMTP.Protocol do
  defmodule Envelope do
    defstruct from: nil,
      to: [],
      data: <<>>,
      expected_size: 0,
      auth: {<<>>, <<>>}

    @type t :: %__MODULE__{
      from: binary,
      to: [binary],
      data: binary,
      expected_size: pos_integer,
      auth: {binary, binary}
    }
  end

  defmodule State do
    defstruct [
      ref: nil,
      socket: nil,
      transport: nil,

      session_module: nil,
      envelope: nil,
      hostname: nil,
      address: nil,
      session_options: [],
      callback_state: nil,
      tls: false,
      waiting_for_auth: nil,
      auth_data: nil,
      extensions: [],
      read_message: false,
      backlog: [],
      ssl_options: []
    ]
  end

  @moduledoc """
  Port of gen_smtp using Ranch as the listener handler.
  """
  use GenStateMachine, callback_mode: [:handle_event_function, :state_enter]

  @maximum_size 10485760
  @builtin_extensions [{"SIZE", "10485670"}, {"8BITMIME", true}, {"PIPELINING", true}]
  @timeout 180000
  #@timeout 15_000

  @type reason_t :: String.t | iolist
  @type callback_state_t :: String.t | iolist
  @type extensions_t :: [{String.t, String.t}]

  @callback init(hostname :: String.t, session_count :: integer, peer_name :: term, callback_options :: term) :: {:ok, reason_t, callback_state_t} | {:stop, reason_t, callback_state_t} | :ignore
  @callback terminate(reason :: term, callback_state_t) :: :ok
  @callback code_change(old_vsn :: term, callback_state_t, extra :: term) :: {:ok, callback_state_t} | term

  @callback handle_AUTH(auth_type :: atom, username :: String.t, credential :: String.t, callback_state_t) :: {:ok, callback_state_t} | term
  @callback handle_DATA(from :: String.t, to :: String.t, data :: binary, callback_state_t) :: {:ok, reference :: reason_t, callback_state_t} | {:error, reason_t, callback_state_t}
  @callback handle_HELO(hostname :: String.t, callback_state_t) :: {:ok, max_size :: integer, callback_state_t} | {:ok, callback_state_t} | {:error, reason_t, callback_state_t}
  @callback handle_EHLO(hostname :: String.t, extensions_t, callback_state_t) :: {:ok, extensions_t, callback_state_t} | {:error, reason_t, callback_state_t}
  @callback handle_MAIL(address :: String.t, callback_state_t) :: {:ok, callback_state_t} | {:error, reason_t, callback_state_t}
  @callback handle_MAIL_extension(extension :: String.t, callback_state_t) :: {:ok, callback_state_t} | :error
  @callback handle_RCPT(address :: String.t, callback_state_t) :: {:ok, callback_state_t} | {:error, reason_t, callback_state_t}
  @callback handle_RCPT_extension(extension :: String.t, callback_state_t) :: {:ok, callback_state_t} | :error
  @callback handle_RSET(callback_state_t) :: callback_state_t
  @callback handle_VRFY(address :: String.t, callback_state_t) :: {:ok, reply :: reason_t, callback_state_t} | {:error, message :: reason_t, callback_state_t}
  @callback handle_STARTTLS(callback_state_t) :: callback_state_t
  @callback handle_other(verb :: String.t, args :: String.t, callback_state_t) :: {message :: reason_t, callback_state_t}

  def start_link(ref, socket, transport, options) do
    GenStateMachine.start_link(__MODULE__, [ref: ref, socket: socket, transport: transport, options: options], [])
  end

  def init(options) do
    ref = options[:ref]
    socket = options[:socket]
    transport = options[:transport]
    opts = options[:options]
    state = struct(State, Enum.into(opts, %{}))
    state = %{state | ref: ref, socket: socket, transport: transport}
    Logger.debug [
      "#{__MODULE__}:",
      " initialized protocol",
      " pid=", inspect(self()),
      " ref=", inspect(ref),
      " socket=", inspect(socket),
      " transport=", inspect(transport),
    ]
    {:ok, :wait_for_ack, state}
  end

  def terminate(reason, _action, state) do
    state.session_module.terminate(reason, state.callback_state)
    :normal
  end

  def get_extension(extensions, key) do
    Enum.find(extensions, fn
      {^key, _} -> true
      _ -> false
    end)
  end

  def reset_auth(state) do
    {:ok, %{state | waiting_for_auth: nil, auth_data: nil, envelope: %{state.envelope | auth: {<<>>, <<>>}}}}
  end

  def try_auth(socket, transport, auth_type, username, credential, state) do
    {:ok, state} = reset_auth(state)

    if function_exported?(state.session_module, :handle_AUTH, 4) do
      case state.session_module.handle_AUTH(auth_type, username, credential, state.callback_state) do
        {:ok, callback_state} ->
          transport.send(socket, "235 Authentication successful\r\n")
          {:ok, %{state | callback_state: callback_state, envelope: %Envelope{state.envelope | auth: {username, credential}}}}

        _ ->
          transport.send(socket, "535 Authentication failed\r\n")
          {:ok, state}
      end
    else
      Logger.error("Please define #{state.session_module}.handle_AUTH/4 or remove AUTH from your module extensions.")
      transport.send(socket, "535 Authentication failed (#5.7.1)\r\n")
      {:ok, state}
    end
  end

  def handle_plain_auth(socket, transport, parameters, state) do
    case Base.decode64(parameters) do
      {:ok, value} ->
        case String.split(value, <<0>>) do
          [_identity, username, password] ->
            try_auth(socket, transport, :plain, username, password, state)

          [username, password] ->
            try_auth(socket, transport, :plain, username, password, state)

          _ ->
            transport.send(socket, "501 Malformed AUTH PLAIN\r\n")
            {:ok, state}
        end

      :error ->
        transport.send(socket, "501 Malformed AUTH PLAIN\r\n")
        {:ok, state}
    end
  end

  def handle_mail(socket, transport, addr, state) do
    case state.session_module.handle_MAIL(addr, state.callback_state) do
      {:ok, callback_state} ->
        transport.send(socket, "250 Sender OK\r\n")
        {:ok, %{state | envelope: %{state.envelope | from: addr}, callback_state: callback_state}}

      {:error, message, callback_state} ->
        transport.send(socket, [message, "\r\n"])
        {:ok, %{state | callback_state: callback_state}}
    end
  end

  def handle_rcpt(socket, transport, addr, state) do
    case state.session_module.handle_RCPT(addr, state.callback_state) do
      {:ok, callback_state} ->
        transport.send(socket, "250 Recipient OK\r\n")
        {:ok, %{state | envelope: %{state.envelope | to: state.envelope.to ++ [addr]}, callback_state: callback_state}}

      {:error, message, callback_state} ->
        transport.send(socket, [message, "\r\n"])
        {:ok, %{state | callback_state: callback_state}}
    end
  end

  def handle(socket, transport, {"", _}, state) do
    transport.send(socket, "500 ERROR: bad syntax\r\n")
    {:ok, state}
  end

  def handle(socket, transport, {"HELO", ""}, state) do
    transport.send(socket, "501 Syntax Error: HELO hostname\r\n")
    {:ok, state}
  end

  def handle(socket, transport, {"HELO", hostname}, state) do
    case state.session_module.handle_HELO(hostname, state.callback_state) do
      {:ok, max_size, callback_state} when is_integer(max_size) ->
        transport.send(socket, ["250 ", state.hostname, "\r\n"])
        {:ok, %{state | extensions: [{"SIZE", Integer.to_string(max_size)}], envelope: %Envelope{}, callback_state: callback_state}}

      {:ok, callback_state} ->
        transport.send(socket, ["250 ", state.hostname, "\r\n"])
        {:ok, %{state | callback_state: callback_state, envelope: %Envelope{}}}

      {:error, message, callback_state} ->
        transport.send(socket, [message, "\r\n"])
        {:ok, %{state |callback_state: callback_state}}
    end
  end

  def handle(socket, transport, {"EHLO", ""}, state) do
    transport.send(socket, "501 Syntax Error: EHLO hostname\r\n")
    {:ok, state}
  end

  def handle(socket, transport, {"EHLO", hostname}, state) do
    case state.session_module.handle_EHLO(hostname, @builtin_extensions, state.callback_state) do
      {:error, message, callback_state} ->
        transport.send(socket, [message, "\r\n"])
        {:ok, %{state | callback_state: callback_state}}

      {:ok, extensions, callback_state} ->
        case extensions do
          [] ->
            transport.send(socket, ["250 ", state.hostname, "\r\n"])
            {:ok, %{state | extensions: extensions, callback_state: callback_state}}

          _ ->
            extensions = if state.tls do
              extensions -- [{"STARTTLS", true}]
            else
              extensions
            end

            {_, _, lines} = Enum.reduce(extensions, {1, length(extensions), [["250-", state.hostname, "\r\n"]]}, fn
              {e, true}, {pos, len, acc} when pos == len ->
                {pos, len, [["250 ", e, "\r\n"] | acc]}

              {e, value}, {pos, len, acc} when pos == len ->
                {pos, len, [["250 ", e, " ", value, "\r\n"] | acc]}

              {e, true}, {pos, len, acc} ->
                {pos + 1, len, [["250-", e, "\r\n"] | acc]}

              {e, value}, {pos, len, acc} ->
                {pos + 1, len, [["250-", e, " ", value, "\r\n"] | acc]}
            end)

            transport.send(socket, Enum.reverse(lines))

            {:ok, %{state | extensions: extensions, envelope: %Envelope{}, callback_state: callback_state}}
        end
    end
  end

  def handle(socket, transport, {"AUTH", _}, %{envelope: nil} = state) do
    transport.send(socket, "503 ERROR: send EHLO first\r\n")
    {:ok, state}
  end

  def handle(socket, transport, {"AUTH", args}, %{extensions: extensions, envelope: envelope} = state) do
    {auth_type, parameters} = case String.split(args, " ", parts: 2) do
      [auth_type, parameters] ->
        {auth_type, String.trim_leading(parameters)}

      [auth_type] ->
        {auth_type, nil}
    end

    case get_extension(extensions, "AUTH") do
      nil ->
        transport.send(socket, "502 ERROR: AUTH not implemented\r\n")
        {:ok, state}

      {_, allowed_types} ->
        auth_type = String.upcase(auth_type)

        types =
          allowed_types
          |> String.split(~r/\s+/, trim: true)
          |> Enum.map(&String.upcase/1)

        if Enum.member?(types, auth_type) do
          case auth_type do
            <<"LOGIN">> ->
              transport.send(socket, "334 VXNlcm5hbWU6\r\n")
              {:ok, %{state | waiting_for_auth: :login, envelope: %{envelope | auth: {<<>>, <<>>}}}}

            <<"PLAIN">> when not is_nil(parameters) ->
              handle_plain_auth(socket, transport, parameters, state)

            <<"PLAIN">> ->
              transport.send(socket, "334\r\n")
              {:ok, %{state | waiting_for_auth: :plain, envelope: %{envelope | auth: {<<>>, <<>>}}}}

            <<"CRAM-MD5">> ->
              :crypto.start
              cram_string = Mailmaid.SMTP.Auth.CramMD5.get_string(state.hostname)
              transport.send(socket, ["334 ", cram_string, "\r\n"])
              {:ok, auth_data} = Base.decode64(cram_string)
              {:ok, %{state | waiting_for_auth: :'cram-md5', auth_data: auth_data, envelope: %{envelope | auth: {<<>>, <<>>}}}}
          end
        else
          transport.send(socket, "504 Unrecognized authentication type\r\n")
          {:ok, state}
        end
    end
  end

  def handle(socket, transport, {username64, <<>>}, %{waiting_for_auth: :'cram-md5', envelope: %{auth: {<<>>, <<>>}}, auth_data: auth_data} = state) do
    with {:ok, pair} <- Base.decode64(username64),
         [username, digest] <- String.split(pair, " ") do
      try_auth(socket, transport, :'cram-md5', username, {digest, auth_data}, %{state | auth_data: nil})
    else
      arr when is_list(arr) ->
        transport.send(socket, "501 Malformed CRAM-MD5 username\r\n")
        reset_auth(state)

      :error ->
        transport.send(socket, "501 Malformed CRAM-MD5 username\r\n")
        reset_auth(state)
    end
  end

  def handle(socket, transport, {username64, <<>>}, %{waiting_for_auth: :plain, envelope: %{auth: {<<>>, <<>>}}} = state) do
    handle_plain_auth(socket, transport, username64, state)
  end

  def handle(socket, transport, {username64, <<>>}, %{waiting_for_auth: :login, envelope: %{auth: {<<>>, <<>>}}} = state) do
    case Base.decode64(username64) do
      {:ok, username} ->
        transport.send(socket, "334 UGFzc3dvcmQ6\r\n")
        {:ok, put_in(state.envelope.auth, {username, <<>>})}

      :error ->
        transport.send(socket, "501 Malformed LOGIN username\r\n")
        reset_auth(state)
    end
  end

  def handle(socket, transport, {password64, <<>>}, %{waiting_for_auth: :login, envelope: %{auth: {username, <<>>}}} = state) do
    case Base.decode64(password64) do
      {:ok, password} ->
        try_auth(socket, transport, :login, username, password, state)

      :error ->
        transport.send(socket, "501 Malformed LOGIN password\r\n")
        reset_auth(state)
    end
  end

  def handle(socket, transport, {"MAIL", _}, %{envelope: nil} = state) do
    transport.send(socket, "503 ERROR: send EHLO or HELO first\r\n")
    {:ok, state}
  end

  def handle(socket, transport, {"MAIL", args}, state) do
    case state.envelope.from do
      nil ->
        args = String.trim_leading(args, " ")
        case String.upcase(args) do
          "FROM:" <> _ ->
            <<_ :: binary-5, addr :: binary>> = args
            addr = String.trim_leading(addr)
            case Mailmaid.SMTP.Address.parse(addr) do
              :error ->
                transport.send(socket, "501 Bad sender address syntax\r\n")
                {:ok, state}

              {parsed_address, <<>>} ->
                handle_mail(socket, transport, parsed_address, state)

              {parsed_address, extra_info} ->
                # in the original implementation, the extra_info was upcased
                # this made a mess of the other extensions since their strings would be uppercase
                options = String.split(extra_info, ~r/\s+/)

                res = Enum.reduce(options, state, fn
                  _, {:error, _} = err -> err
                  option, state ->
                    {key, value} = case String.split(option, "=", parts: 2) do
                      [key, value] -> {key, value}
                      [key] -> {key, nil}
                    end

                    # the key is upcased to make it easier to match
                    case String.upcase(key) do
                      "SIZE" ->
                        case get_extension(state.extensions, "SIZE") do
                          nil -> {:error, "555 Unsupported option: SIZE\r\n"}

                          {_, max_size} ->
                            size_i = String.to_integer(value)
                            if size_i > String.to_integer(max_size) do
                              {:error, ["552 Estimated message length ", value, "exceeds limit of ", max_size, "\r\n"]}
                            else
                              %{state | envelope: %{state.envelope | expected_size: size_i}}
                            end
                        end

                      "BODY" ->
                        case get_extension(state.extensions, "8BITMIME") do
                          nil -> {:error, "555 Unsupported option: BODY\r\n"}
                          {_, _} -> state
                        end

                      _ ->
                        case state.session_module.handle_MAIL_extension(option, state.callback_state) do
                          {:ok, callback_state} -> %{state | callback_state: callback_state}

                          :error -> {:error, ["555 Unsupported option: ", value, "\r\n"]}
                        end
                    end
                end)

                case res do
                  {:error, msg} -> transport.send(socket, msg)
                  state -> handle_mail(socket, transport, parsed_address, state)
                end
            end
          _ ->
            transport.send(socket, "501 Syntax Error: MAIL FROM:<address>\r\n")
            {:ok, state}
        end

      _ ->
        transport.send(socket, "503 ERROR: Multiple MAIL command\r\n")
        {:ok, state}
    end
  end

  def handle(socket, transport, {"RCPT", _}, %{envelope: nil} = state) do
    transport.send(socket, "503 ERROR: send EHLO or HELO first\r\n")
    {:ok, state}
  end

  def handle(socket, transport, {"RCPT", _}, %{envelope: %{from: nil}} = state) do
    transport.send(socket, "503 ERROR: send MAIL first\r\n")
    {:ok, state}
  end

  def handle(socket, transport, {"RCPT", args}, state) do
    args = String.trim_leading(args)

    case String.upcase(args) do
      "TO:" <> _ ->
        <<_ :: binary-3, addr :: binary>> = args
        addr = String.trim_leading(addr)
        case Mailmaid.SMTP.Address.parse(addr) do
          :error ->
            transport.send(socket, "501 Bad recipient address syntax\r\n")
            {:ok, state}

          {<<>>, _} ->
            transport.send(socket, "501 Bad recipient address syntax\r\n")
            {:ok, state}

          {parsed_address, <<>>} ->
            handle_rcpt(socket, transport, parsed_address, state)

          {parsed_address, extra_info} ->
            Logger.warn "Unimplemented RCPT TO: with extra_info #{extra_info}"
            handle_rcpt(socket, transport, parsed_address, state)
        end

      _ ->
        transport.send(socket, "501 Syntax Error: RCPT TO:<address>\r\n")
        {:ok, state}
    end
  end

  def handle(socket, transport, {"DATA", <<>>}, %{envelope: nil} = state) do
    transport.send(socket, "503 ERROR: send EHLO or HELO first\r\n")
    {:ok, state}
  end

  def handle(socket, transport, {"DATA", <<>>}, state) do
    case {state.envelope.from, state.envelope.to} do
      {nil, _} ->
        transport.send(socket, "503 ERROR: need MAIL command\r\n")
        {:ok, state}

      {_, []} ->
        transport.send(socket, "503 ERROR: need RCPT command\r\n")
        {:ok, state}

      _ ->
        transport.send(socket, "354 enter mail, end with line containing only '.'\r\n")
        {:ok, %{state | read_message: true}}
    end
  end

  def handle(socket, transport, {"RSET", _}, state) do
    transport.send(socket, "250 OK\r\n")
    envelope = case state.envelope do
      nil -> nil
      _ -> %Envelope{}
    end
    {:ok, %{state | envelope: envelope, callback_state: state.session_module.handle_RSET(state.callback_state)}}
  end

  def handle(socket, transport, {"NOOP", _}, state) do
    transport.send(socket, "250 OK\r\n")
    {:ok, state}
  end

  def handle(socket, transport, {"QUIT", _}, state) do
    transport.send(socket, "221 BYE\r\n")
    {:stop, :quit, state}
  end

  def handle(socket, transport, {"VRFY", addr}, state) do
    case Mailmaid.SMTP.Address.parse(addr) do
      {parsed_address, <<>>} ->
        case state.session_module.handle_VRFY(parsed_address, state.callback_state) do
          {:ok, reply, callback_state} ->
            transport.send(socket, ["250 ", reply, "\r\n"])
            {:ok, %{state | callback_state: callback_state}}

          {:error, message, callback_state} ->
            transport.send(socket, [message, "\r\n"])
            {:ok, %{state | callback_state: callback_state}}
        end
      _ ->
        transport.send(socket, "501 Syntax Error: VRFY username|address\r\n")
        {:ok, state}
    end
  end

  def handle(socket, transport, {"STARTTLS", <<>>}, %{tls: false} = state) do
    case get_extension(state.extensions, "STARTTLS") do
      nil ->
        transport.send(socket, "500 Command Unrecognized\r\n")
        {:ok, state}

      {_, true} ->
        transport.send(socket, "220 OK\r\n")
        case :ssl.handshake(socket, state.ssl_options, 15_000) do
          {:ok, socket} ->
            state = %{state |
              tls: true,
              envelope: nil,
              auth_data: nil,
              waiting_for_auth: nil,
              read_message: false,
              backlog: [],
              callback_state: state.session_module.handle_STARTTLS(state.callback_state)
            }

            {:ok, %{state | socket: socket, transport: :ranch_ssl}}

          {:error, _} ->
            Logger.warn "TLS negotiation failed"
            transport.send(socket, "454 TLS negotiation failed\r\n")
            {:ok, state}
        end
    end
  end

  def handle(socket, transport, {"STARTTLS", <<>>}, state) do
    transport.send(socket, "500 TLS already negoiated\r\n")
    {:ok, state}
  end

  def handle(socket, transport, {"STARTTLS", _}, state) do
    transport.send(socket, "501 Syntax Error (no parameters allowed)\r\n")
    {:ok, state}
  end

  def handle(socket, transport, {cmd, args}, state) do
    case state.session_module.handle_other(cmd, args, state.callback_state) do
      {:noreply, callback_state} ->
        {:ok, %{state | callback_state: callback_state}}

      {message, callback_state} ->
        transport.send(socket, message)
        {:ok, %{state | callback_state: callback_state}}
    end
  end

  defp commit_acc(acc, index, packet, state) do
    string = :binstr.substr(packet, 1, index - 1)
    rest = :binstr.substr(packet, index + 5)
    result = [string | acc] |> Enum.reverse() |> Enum.join

    {:ok, {result, rest}, state}
  end

  def receive_data_loop(_acc, _socket, _transport, _recv_size, size, max_size, state) when max_size > 0 and size > max_size do
    {:error, :size_exceeded, state}
  end

  def receive_data_loop(acc, socket, transport, recv_size, size, max_size, state) do
    allow_bare_newlines = Keyword.get(state.session_options, :allow_bare_newlines, false)
    case transport.recv(socket, recv_size, 1000) do
      {:ok, packet} ->
        last = case acc do
          [] -> ""
          [last | _] -> last
        end
        case Mailmaid.SMTP.Content.check_bare_crlf(packet, last, allow_bare_newlines, 0) do
          :error -> {:error, :bare_newline, state}

          fixed_packet ->
            case :binstr.strpos(fixed_packet, "\r\n.\r\n") do
              0 -> receive_data_loop([fixed_packet | acc], socket, transport, recv_size, size + byte_size(fixed_packet), max_size, state)
              index -> commit_acc(acc, index, fixed_packet, state)
            end
        end

      {:error, :timeout} when recv_size == 0 and length(acc) > 1 ->
        [a, b | acc2] = acc
        packet = :erlang.list_to_binary([b, a])
        case :binstr.strpos(packet, "\r\n.\r\n") do
          0 -> receive_data_loop(acc, socket, transport, 0, size, max_size, state)
          index -> commit_acc(acc2, index, packet, state)
        end

      {:error, :timeout} ->
        receive_data_loop(acc, socket, transport, 0, size, max_size, state)

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  def receive_data(socket, transport, state) do
    max_size = case get_extension(state.extensions, "SIZE") do
      nil -> @maximum_size
      {_, value} -> String.to_integer(value)
    end

    size = 0
    transport.setopts(socket, [packet: :raw])

    case receive_data_loop([], socket, transport, 0, size, max_size, state) do
      {:ok, {data, rest}, state} ->
        state = case rest do
          "" -> state
          _ -> put_in(state.backlog, state.backlog ++ [rest])
        end

        transport.setopts(socket, [packet: :line])

        unescaped_body = :re.replace(data, <<"^\\\.">>, <<>>, [:global, :multiline, {:return, :binary}])
        envelope = %{state.envelope | data: unescaped_body}

        valid = case get_extension(state.extensions, "SIZE") do
          nil -> true
          {_, value} ->
            case byte_size(envelope.data) > String.to_integer(value) do
              true ->
                transport.send(socket, "552 Message too large\r\n")
                false
              false -> true
            end
        end

        if valid do
          case state.session_module.handle_DATA(envelope.from, envelope.to, envelope.data, state.callback_state) do
            {:ok, reference, callback_state} ->
              transport.send(socket, ["250 queued as ", reference, "\r\n"])
              %{state | read_message: false, envelope: %Envelope{}, callback_state: callback_state}

            {:error, message, callback_state} ->
              transport.send(socket, [message, "\r\n"])
              %{state | read_message: false, envelope: %Envelope{}, callback_state: callback_state}
          end
        else
          %{state | read_message: false, envelope: %Envelope{}}
        end

      {:error, :bare_newline, state} ->
        transport.send(socket, "451 Bare newline detected\r\n")
        Logger.warn("bare newline detected")
        %{state | read_message: false, envelope: %Envelope{}}

      {:error, :size_exceeded, state} ->
        transport.send(socket, "552 Message too large\r\n")
        %{state | read_message: false, envelope: %Envelope{}}

      {:error, _reason, state} ->
        %{state | read_message: false, envelope: %Envelope{}}
    end
  end

  def trim_pdu(pdu) do
    pdu
    |> String.trim_trailing("\n")
    |> String.trim_trailing("\r")
    |> String.trim_trailing("\s")
    |> String.trim_leading("\s")
  end

  def handle_pdu(socket, transport, pdu, %{waiting_for_auth: nil} = state) do
    pdu = trim_pdu(pdu)
    case String.split(pdu, " ", parts: 2) do
      [cmd, parameters] ->
        handle(socket, transport, {String.upcase(cmd), String.trim_leading(parameters)}, state)

      [cmd] ->
        cmd = case String.upcase(cmd) do
          "QUIT" -> "QUIT"
          "DATA" -> "DATA"
          "NOOP" -> "NOOP"
          v -> v
        end
        handle(socket, transport, {cmd, ""}, state)
    end
  end

  def handle_pdu(socket, transport, pdu, %{waiting_for_auth: _} = state) do
    pdu = trim_pdu(pdu)
    handle(socket, transport, {pdu, ""}, state)
  end

  @spec end_loop(term, map) :: {:stop, term, map}
  def end_loop(reason, state) do
    :ok = state.transport.close(state.socket)
    case reason do
      :ignore -> {:stop, :normal, state}
      :normal -> {:stop, :normal, state}
      :quit -> {:stop, :normal, state}
      {:error, :closed} -> {:stop, :normal, state}
      _ -> {:stop, reason, state}
    end
  end

  defp do_handle_pdu(pdu, state) do
    case handle_pdu(state.socket, state.transport, pdu, state) do
      {:ok, %{read_message: true} = state} ->
        state = receive_data(state.socket, state.transport, state)
        :ok = state.transport.setopts(state.socket, [packet: :line])
        {:loop, state}
      {:ok, state} -> {:loop, state}
      {:error, _} = err -> end_loop(err, state)
      {:stop, reason, state} -> end_loop(reason, state)
    end
  end

  def loop(%{backlog: []} = state) do
    case state.transport.recv(state.socket, 0, @timeout) do
      {:ok, pdu} -> loop(%{state | backlog: [pdu]})
      {:error, _} = err -> end_loop(err, state)
    end
  end

  def loop(%{backlog: [pdu | pdus]} = state) do
    state = %{state | backlog: pdus}
    case do_handle_pdu(pdu, state) do
      {:loop, state} -> loop(state)
      {:stop, _reason, _state} = res -> res
    end
  end

  def handle_event(:enter, _event, :wait_for_ack, state) do
    Logger.debug [
      "waiting for acknowledgement",
      " ref=", inspect(state.ref),
      " socket=", inspect(state.socket),
      " transport=", inspect(state.transport),
    ]
    {:keep_state, state}
  end

  def handle_event(:info, {:handshake, _module, transport, _port, timeout}, :wait_for_ack, state) do
    Logger.debug [
      "received shoot",
      " ref=", inspect(state.ref),
      " socket=", inspect(state.socket),
      " transport=", inspect(state.transport),
    ]
    # bypass accept_ack and do the handshake here, that way errors can be caught
    case transport.handshake(state.socket, [], timeout) do
      {:ok, _} ->
        Logger.debug [
          "accepted acknowledgement",
          " ref=", inspect(state.ref),
          " socket=", inspect(state.socket),
          " transport=", inspect(state.transport),
        ]
        {:next_state, :protocol_loop, state}
      {:error, _} = err ->
        end_loop(err, state)
    end
  end

  def handle_event(:enter, _event, :protocol_loop, state) do
    {:keep_state, state, [{:state_timeout, 0, :start_loop}]}
  end

  def handle_event(:state_timeout, :start_loop, :protocol_loop, state) do
    :ok = state.transport.setopts(state.socket, [packet: :line])
    state = put_in(state.hostname, "#{state.hostname || :smtp_util.guess_FQDN()}")
    {:ok, {peer_name, _port}} = state.transport.peername(state.socket)

    callbackoptions = Keyword.get(state.session_options, :callbackoptions, [])

    case state.session_module.init(state.hostname, 1, peer_name, callbackoptions) do
      {:ok, banner, callback_state} ->
        state.transport.send(state.socket, ["220 ", banner, "\r\n"])
        state = put_in(state.callback_state, callback_state)
        loop(state)

      {:stop, reason, message} ->
        state.transport.send(state.socket, [message, "\r\n"])
        end_loop(reason, state)

      :ignore ->
        end_loop(:ignore, state)
    end
  end

  def handle_event(type, content, action, state) do
    IO.inspect "Unhandled Event: type=#{type} content=#{inspect content} action=#{action}"
    {:keep_state, state}
  end
end
