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
    defstruct session_module: nil,
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
      backlog: []
  end

  @maximum_size 10485760
  @builtin_extensions [{"SIZE", "10485670"}, {"8BITMIME", true}, {"PIPELINING", true}]
  @timeout 180000

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
    IO.inspect [:try_auth, auth_type, username, credential]
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
        {:ok, %{callback_state: callback_state}}
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
        {:ok, put_in(state.callback_state, callback_state)}
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
    transport.send(socket, "503 ERROR: send EHLO or HELO first\r\n")
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
              cram_string = :smtp_util.get_cram_string(state.hostname)
              transport.send(socket, ["334 ", cram_string, "\r\n"])
              {:ok, %{state | waiting_for_auth: :'cram-md5', auth_data: Base.decode64(cram_string), envelope: %{envelope | auth: {<<>>, <<>>}}}}
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
    IO.inspect {:login, :username, username64}
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
                options =
                  extra_info
                  |> String.split(~r/\s+/)
                  |> Enum.map(&String.upcase/1)

                res = Enum.reduce(options, state, fn
                  _, {:error, _} = err -> err
                  "SIZE=" <> size, state ->
                    case get_extension(state.extensions, "SIZE") do
                      nil ->
                        {:error, "555 Unsupported option: SIZE\r\n"}

                      {_, value} ->
                        size_i = String.to_integer(size)
                        if size_i > String.to_integer(value) do
                          {:error, ["552 Estimated message length ", size, "exceeds limit of ", value, "\r\n"]}
                        else
                          %{state | envelope: %{expected_size: size_i}}
                        end
                    end

                  "BODY=" <> _type, state ->
                    case get_extension(state.extensions, "8BITMIME") do
                      nil -> {:error, "555 Unsupported option: BODY\r\n"}
                      {_, _} -> state
                    end

                  value, state ->
                    case state.session_module.handle_MAIL_extension(value, state.callback_state) do
                      {:ok, callback_state} ->
                        %{state | callback_state: callback_state}

                      :error ->
                        {:error, ["555 Unsupported option: ", value, "\r\n"]}
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
    transport.send(socket, "503 ERROR: send MAIL command first\r\n")
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
    {:stop, :normal, state}
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

      {_, _} ->
        #transport.send(socket, "220 OK\r\n")
        Logger.warn "TODO: STARTTLS"
        transport.send(socket, "502 Command not implemented\r\n")
        {:ok, state}
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
    IO.inspect {:handle_other, cmd, args}
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
    result = acc |> Enum.reverse() |> Enum.join

    IO.inspect result

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
        case rest do
          "" -> state
          _ -> state.backlog ++ [rest]
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

      {:error, reason, state} ->
        %{state | read_message: false, envelope: %Envelope{}}
    end
  end

  def end_loop(socket, transport, reason, state) do
    try do
      state.session_module.terminate(state.callback_state)
    after
      exit(reason)
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
    IO.inspect {:handle_pdu, :no_auth, pdu}
    pdu = trim_pdu(pdu)

    case String.split(pdu, " ", parts: 2) do
      [cmd, parameters] ->
        handle(socket, transport, {String.upcase(cmd), String.trim_leading(parameters)}, state)

      [cmd] ->
        cmd = case String.upcase(cmd) do
          "QUIT" -> "QUIT"
          "DATA" -> "DATA"
          _ -> cmd
        end
        handle(socket, transport, {cmd, ""}, state)
    end
  end

  def handle_pdu(socket, transport, pdu, %{waiting_for_auth: _} = state) do
    IO.inspect {:handle_pdu, :auth, pdu}
    pdu = trim_pdu(pdu)
    handle(socket, transport, {pdu, ""}, state)
  end

  def loop(socket, transport, %{backlog: []} = state) do
    case transport.recv(socket, 0, @timeout) do
      {:ok, data} ->
        case handle_pdu(socket, transport, data, state) do
          {:ok, %{read_message: true} = state} ->
            state = receive_data(socket, transport, state)
            transport.setopts(socket, [packet: :line])
            loop socket, transport, state

          {:ok, state} ->
            loop(socket, transport, state)
          {:stop, reason, _state} -> end_loop(socket, transport, reason, state)
          {:error, reason} -> end_loop(socket, transport, reason, state)
        end
      {:error, reason} ->
        :ok = transport.close(socket)
        end_loop(socket, transport, reason, state)
    end
  end

  def loop(socket, transport, %{backlog: [packet | packets]} = state) do
    state = %{state | backlog: packets}
    case handle_pdu(socket, transport, packet, state) do
      {:ok, %{read_message: true} = state} ->
        state = receive_data(socket, transport, state)
        transport.setopts(socket, [packet: :line])
        loop socket, transport, state

      {:ok, state} -> loop(socket, transport, state)
      {:stop, reason, _state} -> end_loop(socket, transport, reason, state)
      {:error, reason} -> end_loop(socket, transport, reason, state)
    end
  end

  def init(ref, socket, transport, opts \\ []) do
    :ok = :ranch.accept_ack(ref)
    transport.setopts(socket, [packet: :line])
    state = Enum.into(opts, %{})
    state = struct(State, state)
    state = put_in(state.hostname, "#{state.hostname || :smtp_util.guess_FQDN()}")
    {:ok, {peer_name, _port}} = transport.peername(socket)
    callbackoptions = Keyword.get(state.session_options, :callbackoptions, [])
    case state.session_module.init(state.hostname, 1, peer_name, callbackoptions) do
      {:ok, banner, callback_state} ->
        transport.send(socket, ["220 ", banner, "\r\n"])
        state = put_in(state.callback_state, callback_state)
        loop socket, transport, state

      {:stop, reason, message} ->
        transport.send(socket, [message, "\r\n"])
        :ok = transport.close(socket)
        exit(:normal)

      :ignore ->
        :ok = transport.close(socket)
        exit(:normal)
    end
  end

  def start_link(ref, socket, transport, opts) do
    pid = spawn_link(__MODULE__, :init, [ref, socket, transport, opts])
    {:ok, pid}
  end
end
