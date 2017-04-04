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

  describe "parse_request" do
    test "Parsing normal SMTP requests" do
      assert {<<"HELO">>, <<>>} == Session.parse_request(<<"HELO\r\n">>)
      assert {<<"EHLO">>, <<"hell.af.mil">>} == Session.parse_request(<<"EHLO hell.af.mil\r\n">>)
      assert {<<"MAIL">>, <<"FROM:God@heaven.af.mil">>} == Session.parse_request(<<"MAIL FROM:God@heaven.af.mil">>)
    end

    test "Verbs should be uppercased" do
      assert {<<"HELO">>, <<"hell.af.mil">>} == Session.parse_request(<<"helo hell.af.mil">>)
    end

    test "Leading and trailing spaces are removed" do
      assert {<<"HELO">>, <<"hell.af.mil">>} == Session.parse_request(<<" helo   hell.af.mil           ">>)
    end

    test "Blank lines are blank" do
      assert {<<>>, <<>>} == Session.parse_request(<<"">>)
    end
  end

  describe "stray newline test" do

    test "Error out by default" do
      assert <<"foo">> == Session.check_bare_crlf(<<"foo">>, <<>>, false, 0)
      assert :error == Session.check_bare_crlf(<<"foo\n">>, <<>>, false, 0)
      assert :error == Session.check_bare_crlf(<<"fo\ro\n">>, <<>>, false, 0)
      assert :error == Session.check_bare_crlf(<<"fo\ro\n\r">>, <<>>, false, 0)
      assert <<"foo\r\n">> == Session.check_bare_crlf(<<"foo\r\n">>, <<>>, false, 0)
      assert <<"foo\r">> == Session.check_bare_crlf(<<"foo\r">>, <<>>, false, 0)
    end

    test "Fixing them should work" do
      assert <<"foo">> == Session.check_bare_crlf(<<"foo">>, <<>>, :fix, 0)
      assert <<"foo\r\n">> == Session.check_bare_crlf(<<"foo\n">>, <<>>, :fix, 0)
      assert <<"fo\r\no\r\n">> == Session.check_bare_crlf(<<"fo\ro\n">>, <<>>, :fix, 0)
      assert <<"fo\r\no\r\n\r">> == Session.check_bare_crlf(<<"fo\ro\n\r">>, <<>>, :fix, 0)
      assert <<"foo\r\n">> == Session.check_bare_crlf(<<"foo\r\n">>, <<>>, :fix, 0)
    end

    test "Stripping them should work" do
      assert <<"foo">> == Session.check_bare_crlf(<<"foo">>, <<>>, :strip, 0)
      assert <<"foo">> == Session.check_bare_crlf(<<"fo\ro\n">>, <<>>, :strip, 0)
      assert <<"foo\r">> == Session.check_bare_crlf(<<"fo\ro\n\r">>, <<>>, :strip, 0)
      assert <<"foo\r\n">> == Session.check_bare_crlf(<<"foo\r\n">>, <<>>, :strip, 0)
    end

    test "Ignoring them should work" do
      assert <<"foo">> == Session.check_bare_crlf(<<"foo">>, <<>>, :ignore, 0)
      assert <<"fo\ro\n">> == Session.check_bare_crlf(<<"fo\ro\n">>, <<>>, :ignore, 0)
      assert <<"fo\ro\n\r">> == Session.check_bare_crlf(<<"fo\ro\n\r">>, <<>>, :ignore, 0)
      assert <<"foo\r\n">> == Session.check_bare_crlf(<<"foo\r\n">>, <<>>, :ignore, 0)
    end

    test "Leading bare LFs should check the previous line" do
      assert <<"\nfoo\r\n">> == Session.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r">>, false, 0)
      assert <<"\r\nfoo\r\n">> == Session.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r\n">>, :fix, 0)
      assert <<"\nfoo\r\n">> == Session.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r">>, :fix, 0)
      assert <<"foo\r\n">> == Session.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r\n">>, :strip, 0)
      assert <<"\nfoo\r\n">> == Session.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r">>, :strip, 0)
      assert <<"\nfoo\r\n">> == Session.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r\n">>, :ignore, 0)
      assert :error == Session.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r\n">>, false, 0)
      assert <<"\nfoo\r\n">> == Session.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r">>, false, 0)
    end
  end
end
