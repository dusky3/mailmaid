require Logger

defmodule Mailmaid.SMTP.Client.Auth do
  @auth_preference ~w[CRAM-MD5 LOGIN PLAIN]

  import Mailmaid.SMTP.Client.Socket

  defp assert_auth_requirement(socket, options) do
    case :proplists.get_value(:auth, options) do
      {:always, _} ->
        quit(socket)
        throw({:missing_requirement, :auth})

      _ ->
        false
    end
  end

  def do_AUTH_each(_socket, _username, _password, []) do
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

              {:ok, _msg} ->
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

  def do_AUTH(socket, username, password, types) do
    fixed_types = Enum.map(types, &String.upcase/1)
    allowed_types = Enum.filter(@auth_preference, &Enum.member?(fixed_types, &1))
    do_AUTH_each(socket, username, password, allowed_types)
  end

  def to_list_string(string) when is_list(string), do: string
  def to_list_string(binary) when is_binary(binary), do: :erlang.binary_to_list(binary)

  defp do_try_AUTH(socket, options, auth_types)
    when auth_types == [] or auth_types == nil
  do
      assert_auth_requirement(socket, options)
  end

  defp do_try_AUTH(socket, options, :undefined) do
    Logger.warn "FIX, do_try_AUTH with undefined auth_types found!"
    assert_auth_requirement(socket, options)
  end

  defp do_try_AUTH(socket, options, auth_types) do
    if :proplists.is_defined(:username, options) and
       :proplists.is_defined(:password, options) and
       :proplists.is_defined(:auth, options) != :never do

      username = to_list_string(:proplists.get_value(:username, options))
      password = to_list_string(:proplists.get_value(:password, options))

      server_auth_types = Regex.split(~r/\s+/, auth_types)

      auth_settings = :proplists.get_value(:auth, options)
      {_, auth_preference} = auth_settings

      types =
        Enum.reduce(auth_preference, [], fn auth_type, acc ->
          if Enum.member?(server_auth_types, auth_type) do
            [auth_type | acc]
          else
            acc
          end
        end)
        |> Enum.reverse

      case do_AUTH(socket, username, password, types) do
        false ->
          case auth_settings do
            {:always, _} ->
              quit(socket)
              throw({:permanent_failure, :auth_failed})

            _ -> false
          end

        true -> true
      end
    else
      assert_auth_requirement(socket, options)
    end
  end

  def try_AUTH(socket, options, server_auth_types) do
    {requirement, items} = case :proplists.get_value(:auth, options) do
      {requirement, items} ->
        {requirement, List.wrap(items)}

      requirement when is_atom(requirement) ->
        {requirement, @auth_preference}
    end

    options = [{:auth, {requirement, items}} | :proplists.delete(:auth, options)]

    do_try_AUTH(socket, options, server_auth_types)
  end
end
