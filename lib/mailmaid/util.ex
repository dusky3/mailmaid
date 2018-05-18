defmodule Mailmaid.Util do
  @spec parse_address(String.t | tuple) :: tuple
  def parse_address(address) when is_tuple(address) do
    address
  end

  def parse_address(address) when is_binary(address) do
    {:ok, addr} =
      address
      |> String.to_charlist()
      |> :inet.parse_address()
    addr
  end

  @spec encode_address(String.t | tuple) :: String.t
  def encode_address(tup) when is_tuple(tup) do
    tup
    |> :inet.ntoa()
    |> to_string()
  end

  def encode_address(bin) when is_binary(bin), do: bin

  def is_ipv6_address?({_a, _b, _c, _d, _e, _f, _g, _h}), do: true
  def is_ipv6_address?(_), do: false
end
