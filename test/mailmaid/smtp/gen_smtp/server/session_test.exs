require Base

defmodule Mailmaid.SMTP.GenSMTP.Server.SessionTest do
  use ExUnit.Case
  alias Mailmaid.SMTP.GenSMTP.Server.Session
  doctest Session

  def await_socket do
    receive do
      {:tcp, csock, packet} ->
        :socket.active_once(csock)
        {csock, packet}
    end
  end

  def send_and_wait(socket, payload) do
    :socket.send(socket, payload)
    await_socket()
  end

  def wait_for_auth_lines do
    foo = fn f, acc ->
      receive do
        {:tcp, csock, raw_packet} ->
          case {:tcp, csock, "#{raw_packet}"} do
            {:tcp, csock, "250-AUTH" <> _packet} ->
              :socket.active_once(csock)
              f.(f, true)

            {:tcp, csock, "250-" <> _packet} ->
              :socket.active_once(csock)
              f.(f, acc)

            {:tcp, csock, "250 AUTH" <> _packet} ->
              :socket.active_once(csock)
              true

            {:tcp, csock, "250 " <> _packet} ->
              :socket.active_once(csock)
              acc

            {:tcp, csock, _} ->
              :socket.active_once(csock)
              :error
          end
      end
    end

    foo.(foo, false)
  end

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

  describe "Auth" do
    setup do
      parent = self()

      spawn_link(fn ->
        {:ok, listen_sock} = :socket.listen(:tcp, 9876, [:binary])
        {:ok, x} = :socket.accept(listen_sock)

        :socket.controlling_process(x, parent)

        send(parent, x)
      end)
      {:ok, csock} = :socket.connect(:tcp, 'localhost', 9876)
      {:ok, ssock} = receive do
        ssock when is_port(ssock) -> {:ok, ssock}
      end

      {:ok, pid} = Session.start(ssock, Mailmaid.SMTP.ServerExample, [hostname: "localhost", sessioncount: 1, callbackoptions: [auth: true]])
      :socket.controlling_process(ssock, pid)
      on_exit fn ->
        :socket.close(csock)
      end
      %{socket: csock, pid: pid}
    end

    test "EHLO response includes AUTH", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {_csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()
    end

    test "AUTH before EHLO is error", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {_csock, packet} = send_and_wait(csock, "AUTH CRAZY\r\n")

      assert "503 " <> _ = "#{packet}"
    end

    test "Unknown authentication type", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()

      {_csock, packet} = send_and_wait(csock, "AUTH CRAZY\r\n")

      assert "504 Unrecognized authentication type\r\n" = "#{packet}"
    end

    test "A successful AUTH PLAIN", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()
      {csock, packet} = send_and_wait(csock, "AUTH PLAIN\r\n")
      assert "334\r\n" = "#{packet}"

      str = "\0username\0PaSSw0rd" |> :base64.encode()
      {csock, packet} = send_and_wait(csock, [str, "\r\n"])

      assert "235 Authentication successful.\r\n" == "#{packet}"
    end

    test "A successful AUTH PLAIN with an identity", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()
      {csock, packet} = send_and_wait(csock, "AUTH PLAIN\r\n")
      assert "334\r\n" = "#{packet}"

      str = "username\0username\0PaSSw0rd" |> :base64.encode()
      {csock, packet} = send_and_wait(csock, [str, "\r\n"])

      assert "235 Authentication successful.\r\n" == "#{packet}"
    end

    test "A successful immediate AUTH PLAIN", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()

      str = "\0username\0PaSSw0rd" |> :base64.encode()
      {csock, packet} = send_and_wait(csock, ["AUTH PLAIN ", str, "\r\n"])
      assert "235 Authentication successful.\r\n" == "#{packet}"
    end

    test "A successful immediate AUTH PLAIN with an identity", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()

      str = "username\0username\0PaSSw0rd" |> :base64.encode()
      {csock, packet} = send_and_wait(csock, ["AUTH PLAIN ", str, "\r\n"])
      assert "235 Authentication successful.\r\n" == "#{packet}"
    end

    test "An unsuccessful immediate AUTH PLAIN", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()

      str = "username\0username\0PaSSw0rd2" |> :base64.encode()
      {csock, packet} = send_and_wait(csock, ["AUTH PLAIN ", str, "\r\n"])
      assert "535 Authentication failed.\r\n" == "#{packet}"
    end

    test "An unsuccessful AUTH PLAIN", %{socket: csock}  do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()
      {csock, packet} = send_and_wait(csock, "AUTH PLAIN\r\n")
      assert "334\r\n" = "#{packet}"

      str = "\0username\0NotThePassword" |> :base64.encode()
      {csock, packet} = send_and_wait(csock, [str, "\r\n"])

      assert "535 Authentication failed.\r\n" == "#{packet}"
    end

    test "A successful AUTH LOGIN", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()
      {csock, packet} = send_and_wait(csock, "AUTH LOGIN\r\n")

      assert "334 VXNlcm5hbWU6\r\n" = "#{packet}"

      ustr = :base64.encode("username")
      {csock, packet} = send_and_wait(csock, [ustr, "\r\n"])

      assert "334 UGFzc3dvcmQ6\r\n" = "#{packet}"
      pstr = :base64.encode("PaSSw0rd")
      {csock, packet} = send_and_wait(csock, [pstr, "\r\n"])

      assert "235 Authentication successful.\r\n" == "#{packet}"
    end

    test "An unsuccessful AUTH LOGIN", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()
      {csock, packet} = send_and_wait(csock, "AUTH LOGIN\r\n")

      assert "334 VXNlcm5hbWU6\r\n" = "#{packet}"

      ustr = :base64.encode("username2")
      {csock, packet} = send_and_wait(csock, [ustr, "\r\n"])

      assert "334 UGFzc3dvcmQ6\r\n" = "#{packet}"
      pstr = :base64.encode("PaSSw0rd")
      {csock, packet} = send_and_wait(csock, [pstr, "\r\n"])

      assert "535 Authentication failed.\r\n" == "#{packet}"
    end

    test "A successful AUTH CRAM-MD5", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()
      {csock, packet} = send_and_wait(csock, "AUTH CRAM-MD5\r\n")

      assert "334 " <> _ = "#{packet}"

      ["334", seed64] = "#{packet}" |> String.trim_trailing("\r\n") |> String.split(" ")
      {:ok, seed} = Base.decode64(seed64)
      digest = :smtp_util.compute_cram_digest("PaSSw0rd", seed)
      str = "username #{digest}" |> :base64.encode()

      {csock, packet} = send_and_wait(csock, [str, "\r\n"])
      assert "235 Authentication successful.\r\n" == "#{packet}"
    end

    test "An unsuccessful AUTH CRAM-MD5", %{socket: csock} do
      :socket.active_once(csock)

      {csock, packet} = await_socket()
      assert "220 localhost" <> _stuff = "#{packet}"

      {csock, packet} = send_and_wait(csock, "EHLO somehost.com\r\n")
      assert "250-localhost\r\n" = "#{packet}"

      assert true == wait_for_auth_lines()
      {csock, packet} = send_and_wait(csock, "AUTH CRAM-MD5\r\n")

      assert "334 " <> _ = "#{packet}"

      ["334", seed64] = "#{packet}" |> String.trim_trailing("\r\n") |> String.split(" ")
      {:ok, seed} = Base.decode64(seed64)
      digest = :smtp_util.compute_cram_digest("Passw0rd", seed)
      str = "username #{digest}" |> :base64.encode()

      {csock, packet} = send_and_wait(csock, [str, "\r\n"])
      assert "535 Authentication failed.\r\n" == "#{packet}"
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
