defmodule Mailmaid.SMTP.Server.SessionTest do
  use ExUnit.Case
  alias Mailmaid.SMTP.Server.Session
  doctest Session

  describe "parse_encoded_address" do
    test "Valid addresses should parse" do
      assert {<<"God@heaven.af.mil">>, <<>>} == Session.parse_encoded_address(<<"<God@heaven.af.mil>">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Session.parse_encoded_address(<<"<\\God@heaven.af.mil>">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Session.parse_encoded_address(<<"<\"God\"@heaven.af.mil>">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Session.parse_encoded_address(<<"<@gateway.af.mil,@uucp.local:\"\\G\\o\\d\"@heaven.af.mil>">>)
      assert {<<"God2@heaven.af.mil">>, <<>>} == Session.parse_encoded_address(<<"<God2@heaven.af.mil>">>)
      assert {<<"God+extension@heaven.af.mil">>, <<>>} == Session.parse_encoded_address(<<"<God+extension@heaven.af.mil>">>)
      assert {<<"God~*$@heaven.af.mil">>, <<>>} == Session.parse_encoded_address(<<"<God~*$@heaven.af.mil>">>)
    end

    test "Addresses that are sorta valid should parse" do
      assert {<<"God@heaven.af.mil">>, <<>>} == Session.parse_encoded_address(<<"God@heaven.af.mil">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Session.parse_encoded_address(<<"God@heaven.af.mil ">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Session.parse_encoded_address(<<" God@heaven.af.mil ">>)
      assert {<<"God@heaven.af.mil">>, <<>>} == Session.parse_encoded_address(<<" <God@heaven.af.mil> ">>)
    end

    test "Addresses containing unescaped <> that aren't at start/end should fail" do
      assert :error == Session.parse_encoded_address(<<"<<">>)
      assert :error == Session.parse_encoded_address(<<"<God<@heaven.af.mil>">>)
    end

    test "Address that begins with < but doesn't end with a > should fail" do
      assert :error == Session.parse_encoded_address(<<"<God@heaven.af.mil">>)
      assert :error == Session.parse_encoded_address(<<"<God@heaven.af.mil ">>)
    end

    test "Address that begins without < but ends with a > should fail" do
      assert :error == Session.parse_encoded_address(<<"God@heaven.af.mil>">>)
    end

    test "Address longer than 320 characters should fail" do
      mega_address = :erlang.list_to_binary(:lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ ["@"] ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122) ++ :lists.seq(97, 122))
      assert :error == Session.parse_encoded_address(mega_address)
    end

    test "Address with an invalid route should fail" do
      assert :error == Session.parse_encoded_address(<<"<@gateway.af.mil God@heaven.af.mil>">>)
    end

    test "Empty addresses should parse OK" do
      assert {<<>>, <<>>} == Session.parse_encoded_address(<<"<>">>)
      assert {<<>>, <<>>} == Session.parse_encoded_address(<<" <> ">>)
    end

    test "Completely empty addresses are an error" do
      assert :error == Session.parse_encoded_address(<<"">>)
      assert :error == Session.parse_encoded_address(<<" ">>)
    end

    test "addresses with trailing parameters should return the trailing parameters" do
      assert {<<"God@heaven.af.mil">>, <<"SIZE=100 BODY=8BITMIME">>} == Session.parse_encoded_address(<<"<God@heaven.af.mil> SIZE=100 BODY=8BITMIME">>)
    end
  end

end
