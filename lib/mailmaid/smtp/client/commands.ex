require Logger

defmodule Mailmaid.SMTP.Client.Commands do
  @default_timeout 1_200_000

  def read_multiline_reply(socket, code, acc, timeout \\ @default_timeout) do
    case :socket.recv(socket, 0, timeout) do
      {:ok, packet} ->
        case packet do
          <<^code :: binary-size(3), " ", _rest :: binary>> ->
            {:ok, socket, Enum.reverse([packet | acc])}

          <<^code :: binary-size(3), "-", _rest :: binary>> ->
            read_multiline_reply(socket, code, [packet | acc], timeout)

          _ ->
            {:error, socket, {:unexpected_response, Enum.reverse([packet | acc])}}
        end

      {:error, reason} ->
        {:error, socket, {:connection_error, reason}}
    end
  end

  def read_possible_multiline_reply(socket, timeout \\ @default_timeout) do
    case :socket.recv(socket, 0, timeout) do
      {:ok, packet} ->
        case packet do
          <<code :: binary-size(3), "-", _rest :: binary>> ->
            read_multiline_reply(socket, code, [packet], timeout)
          _ ->
            {:ok, socket, [packet]}
        end

      {:error, reason} ->
        {:error, socket, reason}
    end
  end

  defp wrap_address("<" <> _rest = str), do: str
  defp wrap_address(str), do: "<#{str}>"

  def read_and_handle_common_reply(socket, timeout \\ @default_timeout) do
    case read_possible_multiline_reply(socket, timeout) do
      {:ok, socket, [<<"250", _line :: binary>> | _rest] = messages} -> {:ok, socket, messages}
      {:ok, socket, [<<"251", _line :: binary>> | _rest] = messages} -> {:ok, socket, messages}
      {:ok, socket, [<<"4", _line :: binary>> | _rest] = messages} -> {:error, socket, {:temporary_error, messages}}
      {:ok, socket, messages} -> {:error, socket, {:permanent_failure, messages}}
      {:error, _, _} = err -> err
    end
  end

  def read_auth_reply(socket, timeout \\ @default_timeout) do
    case read_possible_multiline_reply(socket, timeout) do
      {:ok, socket, ["235" <> _line | _rest] = messages} ->
        {:ok, socket, messages}
      {:ok, socket, messages} ->
        {:error, socket, {:auth_error, messages}}
      {:error, socket, reason} ->
        {:error, socket, reason}
    end
  end

  @spec send_line(Port.t, String.t | list) :: :ok | {:error, term}
  def send_line(socket, line) do
    data = [line, "\r\n"]
    :socket.send(socket, data)
  end

  def cmd(socket, cmd, args \\ [])
  def cmd(socket, cmd, []), do: send_line(socket, [cmd])
  def cmd(socket, cmd, args), do: send_line(socket, [cmd, " ", args])

  def ehlo(socket, domain) do
    cmd(socket, "EHLO", [domain])
    read_and_handle_common_reply(socket)
  end

  def helo(socket, domain) do
    cmd(socket, "HELO", [domain])
    read_and_handle_common_reply(socket)
  end

  def auth(socket, "PLAIN", username, password) do
    auth_string64 = Base.encode64("\0#{username}\0#{password}")
    cmd(socket, "AUTH", ["PLAIN ", auth_string64])
    read_auth_reply(socket)
  end

  def auth(socket, "LOGIN", username, password) do
    cmd(socket, "AUTH", ["LOGIN"])
    case read_possible_multiline_reply(socket) do
      {:ok, socket, ["334 " <> username_prompt | _rest] = messages} ->
        username_prompt
        |> String.trim_trailing()
        |> Base.decode64!()
        |> String.downcase()
        |> case do
          "username:" ->
            username64 = Base.encode64(username)
            send_line(socket, username64)

            case read_possible_multiline_reply(socket) do
              {:ok, socket, ["334 " <> password_prompt | _rest] = messages} ->
                password_prompt
                |> String.trim_trailing()
                |> Base.decode64!()
                |> String.downcase()
                |> case do
                  "password:" ->
                    password64 = Base.encode64(password)
                    send_line(socket, password64)
                    read_auth_reply(socket)
                  _ -> {:error, socket, {:unexpected_login_response, messages}}
                end
              {:ok, socket, messages} -> {:error, socket, {:unexpected_login_response, messages}}
              {:error, socket, messages} -> {:error, socket, {:login_error, messages}}
            end
          _ -> {:error, socket, {:unexpected_login_response, messages}}
        end
      {status, socket, messages} when status in [:error, :ok] ->
        {:error, socket, {:unexpected_login_response, messages}}
    end
  end

  def auth(socket, "CRAM-MD5", username, password) do
    cmd(socket, "AUTH", ["CRAM-MD5"])
    case read_possible_multiline_reply(socket) do
      {:ok, socket, ["334" <> line | _rest]} ->
        seed64 = String.trim(line)
        seed = Base.decode64!(seed64)
        digest = :smtp_util.compute_cram_digest(password, seed)
        auth_string64 =
          [username, " ", digest]
          |> Enum.join()
          |> Base.encode64()

        send_line(socket, auth_string64)
        read_auth_reply(socket)
      {status, socket, messages} when status in [:error, :ok] ->
        {:error, socket, {:unexpected_cram_md5_response, messages}}
    end
  end

  def mail_from(socket, address) do
    cmd(socket, "MAIL", ["FROM: ", wrap_address(address)])
    read_and_handle_common_reply(socket)
  end

  def rcpt_to(socket, address) do
    cmd(socket, "RCPT", ["TO: ", wrap_address(address)])
    read_and_handle_common_reply(socket)
  end

  def data(socket, body) do
    cmd(socket, "DATA")
    case read_possible_multiline_reply(socket) do
      {:ok, socket, [<<"354", _line :: binary>> | _rest]} ->
        escaped_body = :re.replace(body, <<"^\\\.">>, <<"..">>, [:global, :multiline, {:return, :binary}])
        :socket.send(socket, [escaped_body, "\r\n.\r\n"])
        read_and_handle_common_reply(socket)
      {:ok, socket, [<<"4", _line :: binary>> | _rest] = messages} -> {:error, socket, {:temporary_error, messages}}
      {:ok, socket, messages} -> {:error, socket, {:permanent_failure, messages}}
      {:error, _socket, _reason} = err -> err
    end
  end

  def starttls(socket) do
    cmd(socket, "STARTTLS")
    case read_possible_multiline_reply(socket) do
      {:ok, socket, [<<"220", _line :: binary>> | _rest]} ->
        case :socket.to_ssl_client(socket, [], 5000) do
          {:ok, ssl_socket} ->
            {:ok, ssl_socket, []}
          {:error, reason} = err ->
            Logger.error ["Connection upgrade error: ", inspect(reason)]
            {:error, socket, {:permanent_failure, reason}}
        end
      {:ok, socket, [<<"4", _line :: binary>> | _rest] = messages} -> {:error, socket, {:temporary_error, messages}}
      {:ok, socket, messages} -> {:error, socket, {:permanent_failure, messages}}
      {:error, _socket, _reason} = err -> err
    end
  end

  def help(socket) do
    cmd(socket, "HELP")
    read_and_handle_common_reply(socket)
  end

  def noop(socket) do
    cmd(socket, "NOOP")
    read_and_handle_common_reply(socket)
  end

  def quit(socket) do
    cmd(socket, "QUIT")
    :socket.close(socket)
    {:ok, socket, []}
  end
end
