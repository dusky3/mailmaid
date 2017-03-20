defmodule Mailmaid.SMTP.Client do
  @default_options [
    ssl: false,
    tls: :if_available,
    auth: :if_available,
    hostname: :smtp_util.guess_FQDN(),
    retries: 1
  ]

  @auth_preference ~w[CRAM-MD5 LOGIN PLAIN]

  @timeout 1_200_000
  #@timeout 10_000

  def send(email, options) do
    send(email, options, nil)
  end

  def send(email, options, callback) do
    new_options = :lists.ukeymerge(1, :lists.sort(options), :lists.sort(@default_options))
    case check_options(new_options) do
      :ok when is_function(callback) ->
        spawn(fn ->
          :erlang.process_flag(:trap_exit, true)

          pid = spawn_link(fn ->
            send_it_nonblock(email, new_options, callback)
          end)

          receive do
            {:EXIT, pid, reason} ->
              case reason do
                x when x == :normal or x == :shutdown ->
                  :ok

                error ->
                  callback.({:exit, error})
              end
          end
        end)

      :ok ->
        pid = spawn_link(fn ->
          send_it_nonblock(email, new_options, callback)
        end)

        {:ok, pid}

      {:error, _reason} = err -> err
    end
  end

  def send_blocking(email, options) do
    new_options = :lists.ukeymerge(1, :lists.sort(options), :lists.sort(@default_options))

    case check_options(new_options) do
      :ok -> send_it(email, new_options)

      {:error, _reason} = err -> err
    end
  end

  def send_it_nonblock(email, options, callback) do
    case send_it(email, options) do
      {:error, type, message} when is_function(callback) ->
        callback.({:error, type, message})
        {:error, type, message}

      {:error, type, message}
        :erlang.exit({:error, type, message})

      receipt when is_function(callback) ->
        callback.({:ok, receipt})

      receipt ->
        {:ok, receipt}
    end
  end

  def send_it(email, options) do
    relay_domain = :proplists.get_value(:relay, options)

    mx_records = case :proplists.get_value(:no_mx_lookups, options) do
      true -> []
      _ -> :smtp_util.mxlookup(relay_domain)
    end

    hosts = case mx_records do
      [] -> [{0, relay_domain}]
      _ -> mx_records
    end

    try_smtp_sessions(hosts, email, options, [])
  end

  def try_smtp_sessions([{_distance, host} | _tail] = hosts, email, options, retry_list) do
    try do
      do_smtp_session(host, email, options)
    catch
      fail_msg ->
        handle_smtp_throw(fail_msg, hosts, email, options, retry_list)
    end
  end

  def handle_smtp_throw({:permanent_failure, message}, [{_distance, host} | _tail], _email, _options, _retry_list) do
    {:error, :no_more_hosts, {:permanent_failure, host, message}}
  end

  def handle_smtp_throw({:temporary_failure, :tls_failed}, [{_distance, host} | _tail] = hosts, email, options, retry_list) do
    case :proplists.get_value(:tls, options) do
      :if_available ->
        no_tls_options = [{:tls, :never} | :proplists.delete(:tls, options)]
        try do
          do_smtp_session(host, email, no_tls_options)
        catch
          fail_msg ->
            handle_smtp_throw(fail_msg, hosts, email, options, retry_list)
        end

      _ ->
        try_next_host({:temporary_failure, :tls_failed}, hosts, email, options, retry_list)
    end
  end

  def handle_smtp_throw(fail_msg, hosts, email, options, retry_list) do
    try_next_host(fail_msg, hosts, email, options, retry_list)
  end

  def try_next_host({failure_type, message}, [{_distance, host} | _tail] = hosts, email, options, retry_list) do
    retries = :proplists.get_value(:retries, options)
    retry_count = :proplists.get_value(Host, retry_list)

    case fetch_next_host(retries, retry_count, hosts, retry_list) do
      {[], _new_retry_list} ->
        {:error, :retries_exceeded, {failure_type, host, message}}

      {new_hosts, new_retry_list} ->
        try_smtp_sessions(new_hosts, email, options, new_retry_list)
    end
  end

  def fetch_next_host(retries, retry_count, [{_distance, host} | tail], retry_list) when is_integer(retry_count) and retry_count >= retries do
    {tail, :lists.keydelete(host, 1, retry_list)}
  end

  def fetch_next_host(_retries, retry_count, [{distance, host} | tail], retry_list) when is_integer(retry_count) do
    {tail ++ [{distance, host}], :lists.keydelete(host, 1, retry_list) ++ [{host, retry_count + 1}]}
  end

  def fetch_next_host(0, retry_count, [{_distance, host} | tail], retry_list) do
    {tail, :lists.keydelete(host, 1, retry_list)}
  end

  def fetch_next_host(_retries, _retry_count, [{distance, host} | tail], retry_list) do
    {tail ++ [{distance, host}], :lists.keydelete(Host, 1, retry_list) ++ [{host, 1}]}
  end

  def do_smtp_session(host, email, options) do
    {:ok, socket, _host, _banner} = connect(host, options)

    {:ok, extensions} = try_EHLO(socket, options)
    {socket, extensions} = try_STARTTLS(socket, options, extensions)

    _authed = try_AUTH(socket, options, :proplists.get_value(<<"AUTH">>, extensions))
    receipt = try_sending_it(email, socket, extensions)
    quit(socket)
    receipt
  end

  require Logger

  def try_sending_it({from, to, body}, socket, extensions) do
    try_MAIL_FROM(from, socket, extensions)
    try_RCPT_TO(to, socket, extensions)
    try_DATA(body, socket, extensions)
  end

  defp wrap_address("<" <> _rest = str), do: str
  defp wrap_address(str), do: "<#{str}>"

  def try_MAIL_FROM(from, socket, extensions) do
    from = wrap_address(from)
    :socket.send(socket, ["MAIL FROM: ", from, "\r\n"])

    case read_possible_multiline_reply(socket) do
      {:ok, <<"250", _rest :: binary>>} ->
        true

      {:ok, <<"4", _rest :: binary>> = msg} ->
        quit(socket)
        throw({:temporary_failure, msg})

      {:ok, msg} ->
        quit(socket)
        throw({:permanent_failure, msg})
    end
  end

  def try_RCPT_TO([], socket, extensions) do
    true
  end

  def try_RCPT_TO([to | tail], socket, extensions) do
    to = wrap_address(to)

    payload = ["RCPT TO: ", to, "\r\n"]
    :ok = :socket.send(socket, payload)

    case read_possible_multiline_reply(socket) do
      {:ok, <<"250", _rest :: binary>>} ->
        try_RCPT_TO(tail, socket, extensions)

      {:ok, <<"251", _rest :: binary>>} ->
        try_RCPT_TO(tail, socket, extensions)

      {:ok, <<"4", _rest :: binary>> = msg} ->
        quit(socket)
        throw({:temporary_failure, msg})

      {:ok, msg} ->
        quit(socket)
        throw({:permanent_failure, msg})
    end
  end

  def try_DATA(body, socket, extensions) when is_function(body) do
    try_DATA(body.(), socket, extensions)
  end

  def try_DATA(body, socket, extensions) do
    :socket.send(socket, "DATA\r\n")

    case read_possible_multiline_reply(socket) do
      {:ok, <<"354", _rest :: binary>>} ->
        escaped_body = :re.replace(body, <<"^\\\.">>, <<"..">>, [:global, :multiline, {:return, :binary}])
        :socket.send(socket, [escaped_body, "\r\n.\r\n"])

        case read_possible_multiline_reply(socket) do
          {:ok, <<"250 ", receipt :: binary>>} ->
            receipt

          {:ok, <<"4", _rest :: binary>> = msg} ->
            quit(socket)
            throw({:temporary_failure, msg})

          {:ok, msg} ->
            quit(socket)
            throw({:permanent_failure, msg})
        end

      {:ok, <<"4", _rest :: binary>> = msg} ->
        quit(socket)
        throw({:temporary_failure, msg})

      {:ok, msg} ->
        quit(socket)
        throw({:permanent_failure, msg})

    end
  end

  def try_AUTH(socket, options, auth_types) when auth_types == [] or auth_types == nil do
    case :proplists.get_value(:auth, options) do
      :always ->
        quit(socket)
        throw({:missing_requirement, :auth})

      _ ->
        false
    end
  end

  def try_AUTH(socket, options, :undefined) do
    Logger.warn "FIX, try_AUTH with undefined auth_types found!"
    case :proplists.get_value(:auth, options) do
      :always ->
        quit(socket)
        throw({:missing_requirement, :auth})

      _ -> false
    end
  end

  def try_AUTH(socket, options, auth_types) do
    if :proplists.is_defined(:username, options) and
       :proplists.is_defined(:password, options) and
       :proplists.is_defined(:auth, options) != :never do

      username = to_list_string(:proplists.get_value(:username, options))
      password = to_list_string(:proplists.get_value(:password, options))

      types = Regex.split(~r/\s+/, auth_types)

      case do_AUTH(socket, username, password, types) do
        false ->
          case :proplists.get_value(:auth, options) do
            :always ->
              quit(socket)
              throw({:permanent_failure, :auth_failed})

            _ -> false
          end

        true -> true
      end
    else
      case :proplists.get_value(:auth, options) do
        :always ->
          quit(socket)
          throw({:missing_requirement, :auth})

        _ -> false
      end
    end
  end

  def to_list_string(string) when is_list(string), do: string
  def to_list_string(binary) when is_binary(binary), do: :erlang.binary_to_list(binary)

  def do_AUTH(socket, username, password, types) do
    fixed_types = Enum.map(types, &String.upcase/1)
    allowed_types = Enum.reduce(@auth_preference, [], fn x, acc ->
      if Enum.member?(fixed_types, x) do
        [x | acc]
      else
        acc
      end
    end)

    do_AUTH_each(socket, username, password, allowed_types)
  end

  def do_AUTH_each(socket, _username, _password, []) do
    false
  end

  def do_AUTH_each(socket, username, password, ["CRAM-MD5" | tail]) do
    :socket.send(socket, "AUTH CRAM-MD5\r\n")

    case read_possible_multiline_reply(socket) do
      {:ok, <<"334", rest :: binary>>} ->
        seed64 = :binstr.strip(:binstr.strip(rest, :right, ?\n), :right, ?\r)
        seed = :base64.decode_to_string(seed64)
        digest = :smtp_util.compute_cram_digest(password, seed)
        string = :base64.encode(:erlang.list_to_binary([username, " ", digest]))

        :socket.send(socket, [string, "\r\n"])

        case read_possible_multiline_reply(socket) do
          {:ok, <<"245", _rest :: binary>>} ->
            true

          {:ok, _msg} ->
            do_AUTH_each(socket, username, password, tail)
        end

      {:ok, _something} ->
        do_AUTH_each(socket, username, password, tail)
    end
  end

  def do_AUTH_each(socket, username, password, ["LOGIN" | tail]) do
    :socket.send(socket, "AUTH LOGIN\r\n")

    case read_possible_multiline_reply(socket) do
      {:ok, prompt} when prompt == <<"334 VXNlcm5hbWU6\r\n">> or prompt == <<"334 dXNlcm5hbWU6\r\n">> ->
        u = :base64.encode(username)
        :socket.send(socket, [u, "\r\n"])

        case read_possible_multiline_reply(socket) do
          {:ok, prompt2} when prompt2 == <<"334 UGFzc3dvcmQ6\r\n">> or prompt2 == <<"334 cGFzc3dvcmQ6\r\n">> ->
            p = :base64.encode(password)

            :socket.send(socket, [p, "\r\n"])

            case read_possible_multiline_reply(socket) do
              {:ok, <<"235", _rest :: binary>>} ->
                true

              {:ok, msg} ->
                do_AUTH_each(socket, username, password, tail)
            end

          {:ok, _msg} ->
            do_AUTH_each(socket, username, password, tail)
        end

      {:ok, _something} ->
        do_AUTH_each(socket, username, password, tail)
    end
  end

  def do_AUTH_each(socket, username, password, ["PLAIN" | tail]) do
    auth_string = Base.encode64(<<"\0#{username}\0#{password}">>)

    payload = ["AUTH PLAIN ", auth_string, "\r\n"]
    :socket.send(socket, payload)

    case read_possible_multiline_reply(socket) do
      {:ok, <<"235", _rest :: binary>>} ->
        true

      _ ->
        do_AUTH_each(socket, username, password, tail)
    end
  end

  def do_AUTH_each(socket, username, password, [_type | tail]) do
    do_AUTH_each(socket, username, password, tail)
  end

  def try_EHLO(socket, options) do
    :ok = :socket.send(socket, ["EHLO ", :proplists.get_value(:hostname, options, :smtp_util.guess_FQDN()), "\r\n"])
    case read_possible_multiline_reply(socket) do
      {:ok, <<"500", _rest :: binary>>} ->
        try_HELO(socket, options)

      {:ok, <<"4", _rest :: binary>> = msg} ->
        quit(socket)
        throw({:temporary_failure, msg})

      {:ok, reply} ->
        {:ok, parse_extensions(reply)}
    end
  end

  def try_HELO(socket, options) do
    :ok = :socket.send(socket, ["HELO", :proplists.get_value(:hostname, options, :smtp_util.guess_FQDN()), "\r\n"])

    case read_possible_multiline_reply(socket) do
      {:ok, <<"250", _rest :: binary>>} ->
        {:ok, []}

      {:ok, <<"4", _rest :: binary>> = msg} ->
        quit(socket)
        throw({:temporary_failure, msg})

      {:ok, msg} ->
        quit(socket)
        throw({:permanent_failure, msg})
    end
  end

  def try_STARTTLS(socket, options, extensions) do
    case {:proplists.get_value(:tls, options), :proplists.get_value(<<"STARTTLS">>, extensions)} do
      {atom, true} when atom == :always or atom == :if_available ->
        case {do_STARTTLS(socket, options), atom} do
          {false, :always} ->
            quit(socket)
            throw({:temporary_failure, :tls_failed})

          {false, :if_available} ->
            {socket, extensions}

          {{s, e}, _} ->
            {s, e}
        end

      {:always, _} ->
        quit(socket)
        throw({:missing_requirement, :tls})

      _ ->
        {socket, extensions}
    end
  end

  def do_STARTTLS(socket, options) do
    :socket.send(socket, "STARTTLS\r\n")

    case read_possible_multiline_reply(socket) do
      {:ok, <<"220", _rest :: binary>>} ->
        case :socket.to_ssl_client(socket, [], 5000) do
          {:ok, new_socket} ->
            {:ok, extensions} = try_EHLO(new_socket, options)
            {new_socket, extensions}

          {:EXIT, reason} ->
            quit(socket)
            :error_logger.error_msg("Error in ssl upgrade: ~p.~n", [reason])
            throw {:temporary_failure, :tls_failed}

          {:error, :ssl_not_started} ->
            quit(socket)
            :error_logger.error_msg("SSL not started.~n")
            throw({:permanent_failure, :ssl_not_started})

          _ ->
            false
        end

      {:ok, <<"4", _rest :: binary>> = msg} ->
        quit(socket)
        throw({:temporary_failure, msg})

      {:ok, msg} ->
        quit(socket)
        throw({:permanent_failure, msg})
    end
  end

  def connect(host, options) do
    host = to_list_string(host)

    add_sock_opts = case :proplists.get_value(:sockopts, options) do
      :undefined -> []
      other -> other
    end

    sock_opts = [:binary, {:packet, :line}, {:keepalive, true}, {:active, false} | add_sock_opts]

    proto = case :proplists.get_value(:ssl, options) do
      true -> :ssl
      _ -> :tcp
    end

    port = case :proplists.get_value(:port, options) do
      :undefined when proto == :ssl -> 465
      oport when is_integer(oport) -> oport
      _ -> 25
    end

    case :socket.connect(proto, host, port, sock_opts, 5000) do
      {:ok, socket} ->
        case read_possible_multiline_reply(socket) do
          {:ok, <<"220", banner :: binary>>} ->
            {:ok, socket, host, banner}

          {:ok, <<"4", _rest :: binary>> = msg} ->
            quit(socket)
            throw({:temporary_failure, msg})

          {:ok, msg} ->
            quit(socket)
            throw({:permanent_failure, msg})
        end

      {:error, reason} ->
        throw({:network_failure, {:error, reason}})
    end
  end

  def read_possible_multiline_reply(socket) do
    case :socket.recv(socket, 0, @timeout) do
      {:ok, packet} ->
        case String.slice(packet, 3, 1) do
          <<"-">> ->
            code = :binstr.substr(packet, 1, 3)
            read_multiline_reply(socket, code, [packet])

          _ ->
            {:ok, packet}
        end

      error ->
        throw({:network_failure, error})
    end
  end

  def read_multiline_reply(socket, code, acc) do
    case :socket.recv(socket, 0, @timeout) do
      {:ok, packet} ->
        case {:binstr.substr(packet, 1, 3), :binstr.substr(packet, 4, 1)} do
          {code, <<" ">>} ->
            {:ok, :erlang.list_to_binary(:lists.reverse([packet | acc]))}

          {code, <<"-">>} ->
            read_multiline_reply(socket, code, [packet | acc])

          _ ->
            quit(socket)
            throw({:unexpected_response, :lists.reverse([packet | acc])})
        end

      error ->
        throw({:network_failure, error})
    end
  end

  def quit(socket) do
    :socket.send(socket, "QUIT\r\n")
    :socket.close(socket)
    :ok
  end

  def check_options(options) do
    case :proplists.get_value(:relay, options) do
      :undefined ->
        {:error, :no_relay}

      _ ->
        case :proplists.get_value(:auth, options) do
          atom when atom == :always ->
            case :proplists.is_defined(:username, options) and :proplists.is_defined(:password, options) do
              false -> {:error, :no_credentials}
              true -> :ok
            end

          _ -> :ok
        end
    end
  end

  def parse_extensions(reply) do
    [_ | reply2] = :re.split(reply, "\r\n", [{:return, :binary}, :trim])

    Enum.map(reply2, fn entry ->
      body = :binstr.substr(entry, 5)

      case :re.split(body, " ", [{:return, :binary}, :trim, {:parts, 2}]) do
        [verb, paramters] ->
          {:binstr.to_upper(verb), paramters}

        [body] ->
          case :binstr.strchr(body, ?=) do
            0 -> {:binstr.to_upper(body), true}
            _ -> []
          end
      end
    end)
  end
end
