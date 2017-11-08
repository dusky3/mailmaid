defmodule Mailmaid.SMTP.Auth.CramMD5 do
  defp format_bin(<<>>, acc) do
    Enum.join(Enum.reverse(acc))
  end

  defp format_bin(<<byte, rest :: binary>>, acc) do
    format_bin(rest, [:io_lib.format("~2.16.0b", [byte]) | acc])
  end

  def compute_digest(key, data) do
    bin = :crypto.hmac(:md5, key, data)
    format_bin(bin, [])
  end

  def get_string(hostname) do
    :io_lib.format("<~B.~B@~s>", [:rand.uniform(4294967295), :rand.uniform(4294967295), hostname])
    |> List.flatten
    |> :erlang.list_to_binary
    |> Base.encode64
  end
end
