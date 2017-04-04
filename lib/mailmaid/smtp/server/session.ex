defmodule Mailmaid.SMTP.Server.Session do
  defmodule Envelope do
    defstruct from: nil,
      to: [],
      data: <<>>,
      expectedsize: 0,
      auth: {<<>>, <<>>}

    @type t :: %__MODULE__{
      from: binary,
      to: [binary],
      data: binary,
      expectedsize: pos_integer,
      auth: {binary, binary}
    }
  end

  defmodule State do
    defstruct socket: nil,
      module: nil,
      envelope: nil,
      extensions: [],
      waitingauth: false,
      authdata: nil,
      readmessage: false,
      tls: false,
      callbackstate: nil,
      options: []

    @type t :: %__MODULE__{
      socket: port | tuple,
      module: atom,
      envelope: Envelope.t,
      extensions: [{String.t, String.t}],
      waitingauth: false | :plain | :login | :'cram-md5',
      authdata: binary,
      readmessage: boolean,
      tls: boolean,
      callbackstate: any,
      options: [tuple]
    }
  end

  @maximum_size 10485760
  @builtin_extensions [{"SIZE", "10485670"}, {"8BITMIME", true}, {"PIPELINING", true}]
  @timeout 180000

  def start_link(socket, module, options, config \\ []) do
    GenServer.start_link(__MODULE__, [socket, module, options], config)
  end

  def start(socket, module, options, config \\ []) do
    GenServer.start_link(__MODULE__, [socket, module, options], config)
  end

  def init([socket, module, options]) do
    {:ok, {peer_name, _port}} = :socket.peername(socket)

    hostname = :proplists.get_value(:hostname, options, :smtp_util.guess_FQDN())
    sessioncount = :proplists.get_value(:sessioncount, options, 0)
    callbackoptions = :proplists.get_value(:callbackoptions, options, [])

    case module.init(hostname, sessioncount, peer_name, callbackoptions) do
      {:ok, banner, callbackstate} ->
        :socket.send(socket, ["220 ", banner, "\r\n"])
        :socket.active_once(socket)

        {:ok, %State{socket: socket, module: module, options: options, callbackstate: callbackstate}, @timeout}

      {:stop, reason, message} ->
        :socket.send(socket, [message, "\r\n"])
        :socket.close(socket)

        {:stop, reason}

      :ignore ->
        :socket.close(socket)
        :ignore
    end
  end

  def handle_call(:stop, _from, state) do
    {:stop, :normal, :ok, state}
  end

  def handle_call(request, _from, state) do
    {:reply, {:unknown_call, request}, state}
  end

  def handle_cast(_message, state) do
    {:noreply, state}
  end

  def handle_info({:receive_data, {:error, :size_exceeded}}, %{socket: socket, readmessage: true} = state) do
    :socket.send(socket, "552 Message too large\r\n")
    :socket.active_once(socket)

    {:noreply, %State{state | readmessage: false, envelope: %Envelope{}}, @timeout}
  end

  def handle_info({:receive_data, {:error, :bare_newline}}, %{socket: socket, readmessage: true} = state) do
    :socket.send(socket, "451 Bare newline detected\r\n")
    :io.format("bare newline detected: ~p~n", [self()])
    :socket.active_once(socket)

    {:noreply, %State{state | readmessage: false, envelope: %Envelope{}}, @timeout}
  end

  def handle_info({:receive_data, body, rest}, %{socket: socket, readmessage: true, envelope: env, module: module, callbackstate: old_callback_state, extensions: extensions} = state) do
    case rest do
      <<>> -> :ok
      _ -> send(self(), {:socket.get_proto(socket), socket, rest})
    end

    :socket.setopts(socket, [{:packet, :line}])

    unescaped_body = :re.replace(body, <<"^\\\.">>, <<>>, [:global, :multiline, {:return, :binary}])
    envelope = %Envelope{env | data: unescaped_body}

    valid = case has_extension(extensions, "SIZE") do
      {:true, value} ->
        case byte_size(envelope.data) > String.to_integer(value) do
          true ->
            :socket.send(socket, "552 Message too large\r\n")
            :socket.active_once(socket)
            false

          false ->
            true
        end

      false ->
        true
    end

    case valid do
      true ->
        case module.handle_DATA(envelope.from, envelope.to, envelope.data, old_callback_state) do
          {:ok, reference, callbackstate} ->
            :socket.send(socket, :io_lib.format("250 queued as ~s\r\n", [reference]))
            :socket.active_once(socket)

            {:noreply, %State{state | readmessage: false, envelope: %Envelope{}, callbackstate: callbackstate}, @timeout}

          {:error, message, callbackstate} ->
            :socket.send(socket, [message, "\r\n"])
            :socket.active_once(socket)
            {:noreply, %State{state | readmessage: false, envelope: %Envelope{}, callbackstate: callbackstate}, @timeout}
        end

      false ->
        {:noreply, %State{state | readmessage: false, envelope: %Envelope{}}, @timeout}
    end
  end

  def handle_info({_socket_type, socket, packet}, state) do
    case handle_request(parse_request(packet), state) do
      {:ok, %{extensions: extensions, options: options, readmessage: true} = new_state} ->
        max_size = case has_extension(extensions, "SIZE") do
          {true, value} -> String.to_integer(value)
          false -> @maximum_size
        end

        session = self()
        size = 0
        :socket.setopts(socket, [{:packet, :raw}])
        :erlang.spawn_opt(fn ->
          receive_data([], socket, 0, size, max_size, session, options)
        end, [:link, {:fullsweep_after, 0}])

        {:noreply, new_state, @timeout}

      {:ok, new_state} ->
        :socket.active_once(state.socket)
        {:noreply, new_state, @timeout}

      {:stop, _reason, _new_state} = res -> res
    end
  end

  def handle_info({:tcp_closed, _socket}, state) do
    {:stop, :normal, state}
  end

  def handle_info({:ssl_closed, _socket}, state) do
    {:stop, :normal, state}
  end

  def handle_info(:timeout, %{socket: socket} = state) do
    :socket.send(socket, "421 Error: timeout exceeded\r\n")
    :socket.close(socket)
    {:stop, :normal, state}
  end

  def handle_info(info, state) do
    :io.format("unhandled info message ~p~n", [info])
    {:noreply, state}
  end

  @spec terminate(reason :: term, state :: State.t) :: {:ok, reason :: term, state :: State.t}
  def terminate(reason, state) do
    if state.socket do
      :socket.close(state.socket)
    end
    if state.module do
      state.module.terminate(reason, state.callbackstate)
    else
      {:ok, reason, state}
    end
  end

  def code_change(old_vsn, %{module: module} = state, extra) do
    callbackstate = case module.code_change(old_vsn, state.callbackstate, extra) do
      {:ok, new_callback_state} -> new_callback_state
      _                         -> state.callbackstate
    end

    {:ok, %State{state | callbackstate: callbackstate}}
  end

  def parse_request(packet) do
    request =
      packet
      |> :binstr.strip(:right, ?\n)
      |> :binstr.strip(:right, ?\r)
      |> :binstr.strip(:right, ?\s)
      |> :binstr.strip(:left, ?\s)

    case :binstr.strchr(request, ?\s) do
      0 ->
        case String.upcase(request) do
          <<"QUIT">> = res -> {res, <<>>}
          <<"DATA">> = res -> {res, <<>>}
          _ -> {request, <<>>}
        end

      index ->
        verb = :binstr.substr(request, 1, index - 1)
        parameters = :binstr.strip(:binstr.substr(request, index + 1), :left, ?\s)

        {String.upcase(verb), parameters}
    end
  end

  def handle_request({<<>>, _any}, %{socket: socket} = state) do
    :socket.send(socket, "500 Error: bad syntax\r\n")
    {:ok, state}
  end

  def handle_request({<<"HELO">>, <<>>}, %{socket: socket} = state) do
    :socket.send(socket, "501 Syntax: HELO hostname\r\n")
    {:ok, state}
  end

  def handle_request({<<"HELO">>, hostname}, %{socket: socket, options: options, module: module, callbackstate: old_callback_state} = state) do
    case module.handle_HELO(hostname, old_callback_state) do
      {:ok, max_size, callbackstate} when is_integer(max_size) ->
        :socket.send(socket, ["250 ", :proplists.get_value(:hostname, options, :smtp_util.guess_FQDN()), "\r\n"])

        {:ok, %State{state | extensions: [{"SIZE", :erlang.integer_to_list(max_size)}], envelope: %Envelope{}, callbackstate: callbackstate}}

      {:ok, callbackstate} ->
        :socket.send(socket, ["250 ", :proplists.get_value(:hostname, options, :smtp_util.guess_FQDN()), "\r\n"])
        {:ok, %State{state | envelope: %Envelope{}, callbackstate: callbackstate}}

      {:error, message, callbackstate} ->
        :socket.send(socket, [message, "\r\n"])
        {:ok, %State{callbackstate: callbackstate}}
    end
  end

  def handle_request({<<"EHLO">>, <<>>}, %{socket: socket} = state) do
    :socket.send(socket, "501 Syntax: EHLO hostname\r\n")

    {:ok, state}
  end

  def handle_request({<<"EHLO">>, hostname}, %{socket: socket, options: options, module: module, callbackstate: old_callback_state, tls: tls} = state) do
    case module.handle_EHLO(hostname, @builtin_extensions, old_callback_state) do
      {:ok, extensions, callbackstate} ->
        case extensions do
          [] ->
            :socket.send(socket, ["250 ", :proplists.get_value(:hostname, options, :smtp_util.guess_FQDN()), "\r\n"])

            {:ok, %State{state | extensions: extensions, callbackstate: callbackstate}}

          _ ->
            f = fn
              {e, true}, {pos, len, acc} when pos == len ->
                {pos, len, [["250 ", e, "\r\n"] | acc]}

              {e, value}, {pos, len, acc} when pos == len ->
                {pos, len, [["250 ", e, " ", value, "\r\n"] | acc]}

              {e, true}, {pos, len, acc} ->
                {pos + 1, len, [["250-", e, "\r\n"] | acc]}

              {e, value}, {pos, len, acc} ->
                {pos + 1, len, [["250-", e, " ", value, "\r\n"] | acc]}
            end

            extensions = case tls do
              true -> extensions -- [{"STARTTLS", true}]
              false -> extensions
            end

            hostname = :proplists.get_value(:hostname, options, :smtp_util.guess_FQDN())
            {_, _, response} = :lists.foldl(f, {1, length(extensions), [["250-", hostname, "\r\n"]]}, extensions)
            :socket.send(socket, Enum.reverse(response))

            {:ok, %State{state | extensions: extensions, envelope: %Envelope{}, callbackstate: callbackstate}}
        end

      {:error, message, callbackstate} ->
        :socket.send(socket, [message, "\r\n"])
        {:ok, %State{state | callbackstate: callbackstate}}
    end
  end

  def handle_request({<<"AUTH">>, _args}, %{envelope: nil, socket: socket} = state) do
    :socket.send(socket, "503 Error: send EHLO first\r\n")
    {:ok, state}
  end

  def handle_request({<<"AUTH">>, args}, %{socket: socket, extensions: extensions, envelope: envelope, options: options} = state) do
    {auth_type, parameters} = case :binstr.strchr(args, ?\s) do
      0 -> {args, false}
      index ->
        {:binstr.substr(args, 1, index - 1),
         :binstr.strip(:binstr.substr(args, index + 1), :left, ?\s)}
    end

    case has_extension(extensions, "AUTH") do
      false ->
        :socket.send(socket, "502 Error: AUTH not implemented\r\n")
        {:ok, state}

      {true, available_types} ->
        auth_type = String.upcase(auth_type)
        types =
          available_types
          |> String.split(~r/\s+/, trim: true)
          |> Enum.map(&String.upcase/1)

        if Enum.member?(types, auth_type) do
          case String.upcase(auth_type) do
            <<"LOGIN">> ->
              :socket.send(socket, "334 VXNlcm5hbWU6\r\n")
              {:ok, %State{state | waitingauth: :login, envelope: %Envelope{envelope | auth: {<<>>, <<>>}}}}

            <<"PLAIN">> when parameters != false ->
              # TODO - duplicated below in handle_request waitingauth PLAIN
              case :binstr.split(:base64.decode(parameters), <<0>>) do
                [_identity, username, password] ->
                  try_auth(:plain, username, password, state)

                [username, password] ->
                  try_auth(:plain, username, password, state)

                _ ->
                  # TODO error
                  {:ok, state}
              end

            <<"PLAIN">> ->
              :socket.send(socket, "334\r\n")
              {:ok, %State{state | waitingauth: :plain, envelope: %Envelope{envelope | auth: {<<>>, <<>>}}}}

            <<"CRAM-MD5">> ->
              :crypto.start()
              string = :smtp_util.get_cram_string(:proplists.get_value(:hostname, options, :smtp_util.guess_FQDN()))
              :socket.send(socket, ["334 ", string, "\r\n"])
              {:ok, %State{state | waitingauth: :'cram-md5', authdata: :base64.decode(string), envelope: %Envelope{envelope | auth: {<<>>, <<>>}}}}
          end
        else
          :socket.send(socket, "504 Unrecognized authentication type\r\n")
          {:ok, state}
        end
    end
  end

  def handle_request({username64, <<>>}, %{waitingauth: :'cram-md5', envelope: %{auth: {<<>>, <<>>}}, authdata: authdata} = state) do
    case :binstr.split(:base64.decode(username64), <<" ">>) do
      [username, digest] ->
        try_auth(:'cram-md5', username, {digest, authdata}, %State{state | authdata: nil})

      _ ->
        # TODO: error
        {:ok, %State{waitingauth: false, authdata: nil}}
    end
  end

  def handle_request({username64, <<>>}, %{waitingauth: :plain, envelope: %Envelope{auth: {<<>>, <<>>}}} = state) do
    case :binstr.split(:base64.decode(username64), <<0>>) do
      [_identity, username, password] ->
        try_auth(:plain, username, password, state)

      [username, password] ->
        try_auth(:plain, username, password, state)

      _ ->
        # TODO: error
        {:ok, %State{state | waitingauth: false}}
    end
  end

  def handle_request({username64, <<>>}, %{socket: socket, waitingauth: :login, envelope: %Envelope{auth: {<<>>, <<>>}}} = state) do
    envelope = state.envelope
    username = :base64.decode(username64)

    :socket.send(socket, "334 UGFzc3dvcmQ6\r\n")
    new_state = %State{state | envelope: %Envelope{envelope | auth: {username, <<>>}}}

    {:ok, new_state}
  end

  def handle_request({password64, <<>>}, %{waitingauth: :login, envelope: %Envelope{auth: {username, <<>>}}} = state) do
    password = :base64.decode(password64)
    try_auth(:login, username, password, state)
  end

  def handle_request({<<"MAIL">>, _args}, %{envelope: nil, socket: socket} = state) do
    :socket.send(socket, "503 Error: send HELO/EHLO first\r\n")
    {:ok, state}
  end

  def handle_request({<<"MAIL">>, args}, %{socket: socket, module: module, envelope: envelope, callbackstate: old_callback_state, extensions: extensions} = state) do
    case envelope.from do
      nil ->
        case :binstr.strpos(String.upcase(args), "FROM:") do
          1 ->
            address = :binstr.strip(:binstr.substr(args, 6), :left, ?\s)
            case parse_encoded_address(address) do
              :error ->
                :socket.send(socket, "501 Bad sender address syntax\r\n")
                {:ok, state}

              {parsed_address, <<>>} ->
                case module.handle_MAIL(parsed_address, old_callback_state) do
                  {:ok, callbackstate} ->
                    :socket.send(socket, "250 sender Ok\r\n")
                    new_envelope = %Envelope{envelope | from: parsed_address}
                    {:ok, %State{state | envelope: new_envelope, callbackstate: callbackstate}}

                  {:error, message, callbackstate} ->
                    :socket.send(socket, [message, "\r\n"])
                    {:ok, %State{callbackstate: callbackstate}}
                end

              {parsed_address, extra_info} ->
                options =
                  extra_info
                  |> :binstr.split(<<" ">>)
                  |> Enum.map(&String.upcase/1)

                f = fn
                  (_, {:error, message}) -> {:error, message}

                  (<<"SIZE=", size :: binary>>, inner_state) ->
                    case has_extension(extensions, "SIZE") do
                      {true, value} ->
                        case String.to_integer(:erlang.binary_to_list(size)) > String.to_integer(value) do
                          true ->
                            {:error, ["552 Estimated message length ", size, " exceeds limit of ", value, "\r\n"]}

                          false ->
                            %State{inner_state | envelope: %Envelope{envelope | expectedsize: String.to_integer(:erlang.binary_to_list(size))}}
                        end

                      false ->
                        {:error, "555 Unsupported option SIZE\r\n"}
                    end

                  (<<"BODY=", _body_type :: binary>>, inner_state) ->
                    case has_extension(extensions, "8BITMIME") do
                      {true, _} -> inner_state
                      false -> {:error, "555 Unsupported option BODY\r\n"}
                    end

                  (x, inner_state) ->
                    case module.handle_MAIL_extension(x, old_callback_state) do
                      {:ok, callbackstate} ->
                        %State{inner_state | callbackstate: callbackstate}

                      :error ->
                        {:error, ["555 Unsupported option: ", extra_info, "\r\n"]}
                    end
                end

                case :lists.foldl(f, state, options) do
                  {:error, message} ->
                    :socket.send(socket, message)
                    {:ok, state}

                  new_state ->
                    case module.handle_MAIL(parsed_address, state.callbackstate) do
                      {:ok, callbackstate} ->
                        :socket.send(socket, "250 sender Ok\r\n")
                        {:ok, %State{state | envelope: %Envelope{envelope | from: parsed_address}, callbackstate: callbackstate}}

                      {:error, message, callbackstate} ->
                        :socket.send(socket, [message, "\r\n"])
                        {:ok, %State{new_state | callbackstate: callbackstate}}
                    end
                end
            end
          _ ->
            :socket.send(socket, "501 Syntax: MAIL FROM:<address>\r\n")
            {:ok, state}
        end
      _ ->
        :socket.send(socket, "503 Error: Nested MAIL command\r\n")
        {:ok, state}
    end
  end

  def handle_request({<<"RCPT">>, _args}, %{socket: socket, envelope: nil} = state) do
    :socket.send(socket, "503 Error: need MAIL command\r\n")
    {:ok, state}
  end

  def handle_request({<<"RCPT">>, args}, %{socket: socket, envelope: envelope, module: module, callbackstate: old_callback_state} = state) do
    case :binstr.strpos(String.upcase(args), "TO:") do
      1 ->
        address = :binstr.strip(:binstr.substr(args, 4), :left, ?\s)
        case parse_encoded_address(address) do
          :error ->
            :socket.send(socket, "501 Bad recipient address syntax\r\n")
            {:ok, state}

          {<<>>, _} ->
            :socket.send(socket, "501 Bad recipient address syntax\r\n")
            {:ok, state}

          {parsed_address, <<>>} ->
            case module.handle_RCPT(parsed_address, old_callback_state) do
              {:ok, callbackstate} ->
                :socket.send(socket, "250 recipient Ok\r\n")
                {:ok, %State{state | envelope: %Envelope{envelope | to: envelope.to ++ [parsed_address]}, callbackstate: callbackstate}}

              {:error, message, callbackstate} ->
                :socket.send(socket, [message, "\r\n"])
                {:ok, %State{callbackstate: callbackstate}}
            end

          {parsed_address, extra_info} ->
            # TODO - are there even any RCPT extensions?
            :io.format("To address ~s (parsed as ~s) with extra info ~s~n", [address, parsed_address, extra_info])
            :socket.send(socket, ["555 Unsupported option: ", extra_info, "\r\n"])
            {:ok, state}
        end
      _ ->
        :socket.send(socket, "501 Syntax: RCPT TO:<address>\r\n")
        {:ok, state}
    end
  end

  def handle_request({<<"DATA">>, <<>>}, %{socket: socket, envelope: nil} = state) do
    :socket.send(socket, "503 Error: send HELO/EHLO first\r\n")
    {:ok, state}
  end

  def handle_request({<<"DATA">>, <<>>}, %{socket: socket, envelope: envelope} = state) do
    case {envelope.from, envelope.to} do
      {nil, _} ->
        :socket.send(socket, "503 Error: need MAIL command\r\n")
        {:ok, state}

      {_, []} ->
        :socket.send(socket, "503 Error: need RCPT command\r\n")
        {:ok, state}

      _ ->
        :socket.send(socket, "354 enter mail, end with line containing only '.'\r\n")
        {:ok, %State{state | readmessage: true}}
    end
  end

  def handle_request({<<"RSET">>, _any}, %{socket: socket, envelope: envelope, module: module, callbackstate: old_callback_state} = state) do
    :socket.send(socket, "250 Ok\r\n")
    new_envelope = case envelope do
      nil -> nil
      _ -> %Envelope{}
    end
    {:ok, %State{state | envelope: new_envelope, callbackstate: module.handle_RSET(old_callback_state)}}
  end

  def handle_request({<<"NOOP">>, _any}, %{socket: socket} = state) do
    :socket.send(socket, "250 Ok\r\n")
    {:ok, state}
  end

  def handle_request({<<"QUIT">>, _any}, %{socket: socket} = state) do
    :socket.send(socket, "221 Bye\r\n")
    {:stop, :normal, state}
  end

  def handle_request({<<"VRFY">>, address}, %State{module: module, socket: socket, callbackstate: old_callback_state} = state) do
    case parse_encoded_address(address) do
      {parsed_address, <<>>} ->
        case module.handle_VRFY(parsed_address, old_callback_state) do
          {:ok, reply, callbackstate} ->
            :socket.send(socket, ["250 ", reply, "\r\n"])
            {:ok, %State{state | callbackstate: callbackstate}}

          {:error, message, callbackstate} ->
            :socket.send(socket, [message, "\r\n"])
            {:ok, %State{state | callbackstate: callbackstate}}
        end

      _ ->
        :socket.send(socket, "501 Syntax: VRFY username/address\r\n")
        {:ok, state}
    end
  end

  def handle_request({<<"STARTTLS">>, <<>>}, %State{socket: socket, module: module, tls: false, extensions: extensions, callbackstate: old_callback_state, options: options} = state) do
    case has_extension(extensions, "STARTTLS") do
      {true, _} ->
        :socket.send(socket, "220 OK\r\n")

        options1 = case :proplists.get_value(:certfile, options) do
          :undefined -> []
          certfile ->
            [{:certfile, certfile}]
        end

        options2 = case :proplists.get_value(:keyfile, options) do
          :undefined -> options1
          keyfile ->
            [{:keyfile, keyfile} | options1]
        end

        # TODO: certfile and keyfile should be at configurable locations

        case :socket.to_ssl_server(socket, options2, 5000) do
          {:ok, new_socket} ->
            {:ok, %State{state | socket: new_socket, envelope: nil, authdata: nil, waitingauth: false, readmessage: false, tls: true, callbackstate: module.handle_STARTTLS(old_callback_state)}}

          {:error, reason} ->
            :io.format("SSL handshake failed : ~p~n", [reason])
            :socket.send(socket, "454 TLS negoiation failed\r\n")
        end

      false ->
        :socket.send(socket, "500 Command unrecognized\r\n")
        {:ok, state}
    end
  end

  def handle_request({<<"STARTTLS">>, <<>>}, %{socket: socket} = state) do
    :socket.send(socket, "500 TLS already negotiated\r\n")
    {:ok, state}
  end

  def handle_request({<<"STARTTLS">>, _args}, %{socket: socket} = state) do
    :socket.send(socket, "501 Syntax error (no parameters allowed)\r\n")
    {:ok, state}
  end

  def handle_request({verb, args}, %{socket: socket, module: module, callbackstate: old_callback_state} = state) do
    {message, callbackstate} = module.handle_other(verb, args, old_callback_state)
    maybe_reply(message, socket)
    {:ok, %State{state | callbackstate: callbackstate}}
  end

  def maybe_reply(:noreply, _), do: :ok
  def maybe_reply(message, socket), do: :socket.send(socket, [message, "\r\n"])

  def parse_encoded_address(<<>>), do: :error
  def parse_encoded_address(<<"<@", address :: binary>>) do
    case :binstr.strchr(address, ?:) do
      0 -> :error
      index -> parse_encoded_address(:binstr.substr(address, index + 1), [], {false, true})
    end
  end

  def parse_encoded_address(<<"<", address :: binary>>) do
    parse_encoded_address(address, [], {false, true})
  end

  def parse_encoded_address(<<" ", address :: binary>>) do
    parse_encoded_address(address)
  end

  def parse_encoded_address(address) do
    parse_encoded_address(address, [], {false, false})
  end

  def parse_encoded_address(<<>>, acc, {_quotes, false}) do
    {:erlang.list_to_binary(:lists.reverse(acc)), <<>>}
  end

  def parse_encoded_address(<<>>, _acc, {_quotes, true}) do
    :error
  end

  def parse_encoded_address(_, acc, _) when length(acc) > 320 do
    :error
  end

  def parse_encoded_address(<<"\\", tail :: binary>>, acc, flags) do
    <<h, new_tail :: binary>> = tail
    parse_encoded_address(new_tail, [h | acc], flags)
  end

  def parse_encoded_address(<<"\"", tail :: binary>>, acc, {false, ab}) do
    parse_encoded_address(tail, acc, {true, ab})
  end

  def parse_encoded_address(<<"\"", tail :: binary>>, acc, {true, ab}) do
    parse_encoded_address(tail, acc, {false, ab})
  end

  def parse_encoded_address(<<">", tail :: binary>>, acc, {false, true}) do
    {:erlang.list_to_binary(:lists.reverse(acc)), :binstr.strip(tail, :left, ?\s)}
  end

  def parse_encoded_address(<<">", _tail :: binary>>, _acc, {false, false}) do
    :error
  end

  def parse_encoded_address(<<" ", tail :: binary>>, acc, {false, false}) do
    {:erlang.list_to_binary(:lists.reverse(acc)), :binstr.strip(tail, :left, ?\s)}
  end

  def parse_encoded_address(<<" ", _tail :: binary>>, _acc, {false, true}) do
    :error
  end

  def parse_encoded_address(<<h, tail :: binary>>, acc, {false, ab}) when h >= ?0 and h <= ?9 do
    parse_encoded_address(tail, [h | acc], {false, ab})
  end

  def parse_encoded_address(<<h, tail :: binary>>, acc, {false, ab}) when h >= ?@ and h <= ?Z do
    parse_encoded_address(tail, [h | acc], {false, ab})
  end

  def parse_encoded_address(<<h, tail :: binary>>, acc, {false, ab}) when h >= ?a and h <= ?z do
    parse_encoded_address(tail, [h | acc], {false, ab})
  end

  def parse_encoded_address(<<h, tail :: binary>>, acc, {false, ab}) when h == ?- or h == ?. or h == ?_ do
    parse_encoded_address(tail, [h | acc], {false, ab})
  end

  def parse_encoded_address(<<h, tail :: binary>>, acc, {false, ab}) when h == ?+ or
    h == ?! or h == ?# or h == ?$ or h == ?% or h == ?& or h == ?' or h == ?* or h == ?= or
    h == ?/ or h == ?? or h == ?^ or h == ?` or h == ?{ or h == ?| or h == ?} or h == ?~ do
      parse_encoded_address(tail, [h | acc], {false, ab})
  end

  def parse_encoded_address(_, _acc, {false, _ab}), do: :error

  def parse_encoded_address(<<h, tail :: binary>>, acc, quotes) do
    parse_encoded_address(tail, [h | acc], quotes)
  end

  def has_extension(exts, ext) do
    extension = String.upcase(ext)
    extensions = Enum.map(exts, fn {x, y} ->
      {String.upcase(x), y}
    end)

    case :proplists.get_value(extension, extensions) do
      :undefined -> false
      value -> {true, value}
    end
  end

  def try_auth(auth_type, username, credential, %{module: module, socket: socket, envelope: envelope, callbackstate: old_callback_state} = state) do
    new_state = %State{state | waitingauth: false, envelope: %Envelope{envelope | auth: {<<>>, <<>>}}}

    case :erlang.function_exported(module, :handle_AUTH, 4) do
      true ->
        case module.handle_AUTH(auth_type, username, credential, old_callback_state) do
          {:ok, callbackstate} ->
            :socket.send(socket, "235 Authentication successful.\r\n")
            {:ok, %State{state | callbackstate: callbackstate, envelope: %Envelope{envelope | auth: {username, credential}}}}

          _ ->
            :socket.send(socket, "535 Authentication failed.\r\n")
            {:ok, new_state}
        end

      false ->
        :io.format("Please define handle_AUTH/4 in your server module or remove AUTH from your module extensions~n")
        :socket.send(socket, "535 authentication failed (#5.7.1)\r\n")
        {:ok, new_state}
    end
  end

  def receive_data(_acc, _socket, _, size, max_size, session, _options) when max_size > 0 and size > max_size do
    :io.format("message body size ~B exceeded maximum allowed ~B~n")
    send(session, {:receive_data, {:error, :size_exceeded}})
  end

  def receive_data(acc, socket, recv_size, size, max_size, session, options) do
    case :socket.recv(socket, recv_size, 1000) do
      {:ok, packet} when acc == [] ->
        case check_bare_crlf(packet, <<>>, :proplists.get_value(:allow_bare_newlines, options, false), 0) do
          :error ->
            send(session, {:receive_data, {:error, :bare_newline}})

          fixed_packet ->
            case :binstr.strpos(fixed_packet, "\r\n.\r\n") do
              0 ->
                receive_data([fixed_packet | acc], socket, recv_size, size + byte_size(fixed_packet), max_size, session, options)

              index ->
                string = :binstr.substr(fixed_packet, 1, index - 1)
                rest = :binstr.substr(fixed_packet, index + 5)
                result = :erlang.list_to_binary(:lists.reverse([string | acc]))

                send(session, {:receive_data, result, rest})
            end
        end

      {:ok, packet} ->
        [last | _] = acc
        case check_bare_crlf(packet, last, :proplists.get_value(:allow_bare_newlines, options, false), 0) do
          :error ->
            send(session, {:receive_data, {:error, :bare_newline}})

          fixed_packet ->
            case :binstr.strpos(fixed_packet, "\r\n.\r\n") do
              0 ->
                receive_data([fixed_packet | acc], socket, recv_size, size + byte_size(fixed_packet), max_size, session, options)

              index ->
                string = :binstr.substr(fixed_packet, 1, index - 1)
                rest = :binstr.substr(fixed_packet, index + 5)

                result = :erlang.list_to_binary(:lists.reverse([string | acc]))

                send(session, {:receive_data, result, rest})
            end
        end

      {:error, :timeout} when recv_size == 0 and length(acc) > 1 ->
        [a, b | acc2] = acc
        packet = :erlang.list_to_binary([b, a])
        case :binstr.strpos(packet, "\r\n.\r\n") do
          0 ->
            receive_data(acc, socket, 0, size, max_size, session, options)

          index ->
            string = :binstr.substr(packet, 1, index - 1)
            rest = :binstr.substr(packet, index + 5)
            result = :erlang.list_to_binary(:lists.reverse([string | acc2]))

            send(session, {:receive_data, result, rest})
        end

      {:error, :timeout} ->
        receive_data(acc, socket, 0, size, max_size, session, options)

      {:error, reason} ->
        :io.format("receive error: ~p~n", [reason])
        exit(:receive_error)
    end
  end

  def check_for_bare_crlf(bin, offset) do
    case {:re.run(bin, "(?<!\r)\n", [capture: :none, offset: offset]), :re.run(bin, "\r(?!\n)", [capture: :none, offset: offset])} do
      {:match, _} -> true
      {_, :match} -> true
      _ -> false
    end
  end

  def fix_bare_crlf(bin, offset) do
    options = [{:offset, offset}, {:return, :binary}, :global]
    bin
    |> :re.replace("(?<!\r)\n", "\r\n", options)
    |> :re.replace("\r(?!\n)", "\r\n", options)
  end

  def strip_bare_crlf(bin, offset) do
    options = [{:offset, offset}, {:return, :binary}, :global]

    bin
    |> :re.replace("(?<!\r)\n", "", options)
    |> :re.replace("\r(?!\n)", "", options)
  end

  def check_bare_crlf(binary, _, :ignore, _) do
    binary
  end

  def check_bare_crlf(<<?\n, _rest :: binary>> = bin, prev, op, offset) when byte_size(prev) > 0 and offset == 0 do
    lastchar = :binstr.substr(prev, -1)
    case lastchar do
      <<"\r">> ->
        check_bare_crlf(bin, <<>>, op, 1)

      _ when op == false ->
        :error

      _ ->
        check_bare_crlf(bin, <<>>, op, 0)
    end
  end

  def check_bare_crlf(binary, _prev, op, offset) do
    last = :binstr.substr(binary, -1)

    case last do
      <<"\r">> ->
        new_bin = :binstr.substr(binary, 1, byte_size(binary) - 1)

        case check_for_bare_crlf(new_bin, offset) do
          true when op == :fix ->
            :erlang.list_to_binary([fix_bare_crlf(new_bin, offset), "\r"])

          true when op == :strip ->
            :erlang.list_to_binary([strip_bare_crlf(new_bin, offset), "\r"])

          true -> :error
          false -> binary
        end

      _ ->
        case check_for_bare_crlf(binary, offset) do
          true when op == :fix ->
            fix_bare_crlf(binary, offset)

          true when op == :strip ->
            strip_bare_crlf(binary, offset)

          true -> :error
          false -> binary
        end
    end
  end
end
