defmodule Mailmaid.SMTP.Content do
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
