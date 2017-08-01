defmodule Mailmaid.SMTP.AddressTest do
  use ExUnit.Case
  alias Mailmaid.SMTP.Address

  describe "parse_encoded_address" do
    test "Valid addresses should parse" do
      assert {<<"God@heaven.af.mil">>, <<>>} == Address.parse(<<"<God@heaven.af.mil>">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Address.parse(<<"<\\God@heaven.af.mil>">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Address.parse(<<"<\"God\"@heaven.af.mil>">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Address.parse(<<"<@gateway.af.mil,@uucp.local:\"\\G\\o\\d\"@heaven.af.mil>">>)
      assert {<<"God2@heaven.af.mil">>, <<>>} == Address.parse(<<"<God2@heaven.af.mil>">>)
      assert {<<"God+extension@heaven.af.mil">>, <<>>} == Address.parse(<<"<God+extension@heaven.af.mil>">>)
      assert {<<"God~*$@heaven.af.mil">>, <<>>} == Address.parse(<<"<God~*$@heaven.af.mil>">>)
    end

    test "Addresses that are sorta valid should parse" do
      assert {<<"God@heaven.af.mil">>, <<>>} == Address.parse(<<"God@heaven.af.mil">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Address.parse(<<"God@heaven.af.mil ">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Address.parse(<<" God@heaven.af.mil ">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Address.parse(<<" <God@heaven.af.mil> ">>)
    end

    test "Addresses containing unescaped <> that aren't at start/end should fail" do
      assert :error == Address.parse(<<"<<">>)
      assert :error == Address.parse(<<"<God<@heaven.af.mil>">>)
    end

    test "Address that begins with < but doesn't end with a > should fail" do
      assert :error == Address.parse(<<"<God@heaven.af.mil">>)
      assert :error == Address.parse(<<"<God@heaven.af.mil ">>)
    end

    test "Address that begins without < but ends with a > should fail" do
      assert :error == Address.parse(<<"God@heaven.af.mil>">>)
    end

    test "Address longer than 320 characters should fail" do
      mega_address = :erlang.list_to_binary(:lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ ["@"] ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122))
      assert :error == Address.parse(mega_address)
    end

    test "Address with an invalid route should fail" do
      assert :error == Address.parse(<<"<@gateway.af.mil God@heaven.af.mil>">>)
    end

    test "Empty addresses should parse OK" do
      assert {<<>>, <<>>} == Address.parse(<<"<>">>)
      assert {<<>>, <<>>} == Address.parse(<<" <> ">>)
    end

    test "Completely empty addresses are an error" do
      assert :error == Address.parse(<<"">>)
      assert :error == Address.parse(<<" ">>)
    end

    test "addresses with trailing parameters should return the trailing parameters" do
      assert {<<"God@heaven.af.mil">>, <<"SIZE=100 BODY=8BITMIME">>} == Address.parse(<<"<God@heaven.af.mil> SIZE=100 BODY=8BITMIME">>)
    end
  end
end
