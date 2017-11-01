defmodule Mailmaid.SMTP.Address do
  def parse(<<>>), do: :error
  def parse(<<"<@", address :: binary>>) do
    case :binstr.strchr(address, ?:) do
      0 -> :error
      index -> parse(:binstr.substr(address, index + 1), [], {false, true})
    end
  end

  def parse(<<"<", address :: binary>>) do
    parse(address, [], {false, true})
  end

  def parse(<<" ", address :: binary>>) do
    parse(address)
  end

  def parse(address) do
    parse(address, [], {false, false})
  end

  def parse(<<>>, acc, {_quotes, false}) do
    {:erlang.list_to_binary(:lists.reverse(acc)), <<>>}
  end

  def parse(<<>>, _acc, {_quotes, true}) do
    :error
  end

  def parse(_, acc, _) when length(acc) > 320 do
    :error
  end

  def parse(<<"\\", tail :: binary>>, acc, flags) do
    <<h, new_tail :: binary>> = tail
    parse(new_tail, [h | acc], flags)
  end

  def parse(<<"\"", tail :: binary>>, acc, {false, ab}) do
    parse(tail, acc, {true, ab})
  end

  def parse(<<"\"", tail :: binary>>, acc, {true, ab}) do
    parse(tail, acc, {false, ab})
  end

  def parse(<<">", tail :: binary>>, acc, {false, true}) do
    {:erlang.list_to_binary(:lists.reverse(acc)), :binstr.strip(tail, :left, ?\s)}
  end

  def parse(<<">", _tail :: binary>>, _acc, {false, false}) do
    :error
  end

  def parse(<<" ", tail :: binary>>, acc, {false, false}) do
    {:erlang.list_to_binary(:lists.reverse(acc)), :binstr.strip(tail, :left, ?\s)}
  end

  def parse(<<" ", _tail :: binary>>, _acc, {false, true}) do
    :error
  end

  def parse(<<h, tail :: binary>>, acc, {false, ab}) when h >= ?0 and h <= ?9 do
    parse(tail, [h | acc], {false, ab})
  end

  def parse(<<h, tail :: binary>>, acc, {false, ab}) when h >= ?@ and h <= ?Z do
    parse(tail, [h | acc], {false, ab})
  end

  def parse(<<h, tail :: binary>>, acc, {false, ab}) when h >= ?a and h <= ?z do
    parse(tail, [h | acc], {false, ab})
  end

  def parse(<<h, tail :: binary>>, acc, {false, ab}) when h == ?- or h == ?. or h == ?_ do
    parse(tail, [h | acc], {false, ab})
  end

  def parse(<<h, tail :: binary>>, acc, {false, ab}) when h == ?+ or
    h == ?! or h == ?# or h == ?$ or h == ?% or h == ?& or h == ?' or h == ?* or h == ?= or
    h == ?/ or h == ?? or h == ?^ or h == ?` or h == ?{ or h == ?| or h == ?} or h == ?~ do
      parse(tail, [h | acc], {false, ab})
  end

  def parse(_, _acc, {false, _ab}), do: :error

  def parse(<<h, tail :: binary>>, acc, quotes) do
    parse(tail, [h | acc], quotes)
  end
end
