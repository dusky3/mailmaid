defmodule Mailmaid.SMTP.Client.Socket do
  @timeout 1_200_000
  #@timeout 10_000

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
          {^code, <<" ">>} ->
            {:ok, :erlang.list_to_binary(:lists.reverse([packet | acc]))}

          {^code, <<"-">>} ->
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
end
