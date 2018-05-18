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

  def is_ipv6_address?({_a, _b, _c, _d, _e, _f, _g, _h}), do: true
  def is_ipv6_address?(_), do: false
end
