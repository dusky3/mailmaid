defmodule Mailmaid.SMTP.ContentTest do
  use ExUnit.Case
  alias Mailmaid.SMTP.Content

  describe "stray newline test" do
    test "Error out by default" do
      assert <<"foo">> == Content.check_bare_crlf(<<"foo">>, <<>>, false, 0)
      assert :error == Content.check_bare_crlf(<<"foo\n">>, <<>>, false, 0)
      assert :error == Content.check_bare_crlf(<<"fo\ro\n">>, <<>>, false, 0)
      assert :error == Content.check_bare_crlf(<<"fo\ro\n\r">>, <<>>, false, 0)
      assert <<"foo\r\n">> == Content.check_bare_crlf(<<"foo\r\n">>, <<>>, false, 0)
      assert <<"foo\r">> == Content.check_bare_crlf(<<"foo\r">>, <<>>, false, 0)
    end

    test "Fixing them should work" do
      assert <<"foo">> == Content.check_bare_crlf(<<"foo">>, <<>>, :fix, 0)
      assert <<"foo\r\n">> == Content.check_bare_crlf(<<"foo\n">>, <<>>, :fix, 0)
      assert <<"fo\r\no\r\n">> == Content.check_bare_crlf(<<"fo\ro\n">>, <<>>, :fix, 0)
      assert <<"fo\r\no\r\n\r">> == Content.check_bare_crlf(<<"fo\ro\n\r">>, <<>>, :fix, 0)
      assert <<"foo\r\n">> == Content.check_bare_crlf(<<"foo\r\n">>, <<>>, :fix, 0)
    end

    test "Stripping them should work" do
      assert <<"foo">> == Content.check_bare_crlf(<<"foo">>, <<>>, :strip, 0)
      assert <<"foo">> == Content.check_bare_crlf(<<"fo\ro\n">>, <<>>, :strip, 0)
      assert <<"foo\r">> == Content.check_bare_crlf(<<"fo\ro\n\r">>, <<>>, :strip, 0)
      assert <<"foo\r\n">> == Content.check_bare_crlf(<<"foo\r\n">>, <<>>, :strip, 0)
    end

    test "Ignoring them should work" do
      assert <<"foo">> == Content.check_bare_crlf(<<"foo">>, <<>>, :ignore, 0)
      assert <<"fo\ro\n">> == Content.check_bare_crlf(<<"fo\ro\n">>, <<>>, :ignore, 0)
      assert <<"fo\ro\n\r">> == Content.check_bare_crlf(<<"fo\ro\n\r">>, <<>>, :ignore, 0)
      assert <<"foo\r\n">> == Content.check_bare_crlf(<<"foo\r\n">>, <<>>, :ignore, 0)
    end

    test "Leading bare LFs should check the previous line" do
      assert <<"\nfoo\r\n">> == Content.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r">>, false, 0)
      assert <<"\r\nfoo\r\n">> == Content.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r\n">>, :fix, 0)
      assert <<"\nfoo\r\n">> == Content.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r">>, :fix, 0)
      assert <<"foo\r\n">> == Content.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r\n">>, :strip, 0)
      assert <<"\nfoo\r\n">> == Content.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r">>, :strip, 0)
      assert <<"\nfoo\r\n">> == Content.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r\n">>, :ignore, 0)
      assert :error == Content.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r\n">>, false, 0)
      assert <<"\nfoo\r\n">> == Content.check_bare_crlf(<<"\nfoo\r\n">>, <<"bar\r">>, false, 0)
    end
  end
end
