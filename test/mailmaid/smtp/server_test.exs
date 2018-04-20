defmodule Mailmaid.SMTP.ServerTest do
  use ExUnit.Case, async: false

  def launch_server(cb, options \\ []) do
    {:ok, _pid} = Mailmaid.SMTP.Server.start_link(Mailmaid.SMTP.ServerExample, [
      [
        {:hostname, "mailmaid.localhost"},
        {:port, 9876},
        {:sessionoptions, [
          callbackoptions: [auth: true]
        ]}
        | options
      ]
    ])
    try do
      {:ok, socket} = :ranch_tcp.connect('localhost', 9876, [])
      :ranch_tcp.setopts(socket, [packet: :line])
      cb.(socket, :ranch_tcp)
    after
      :ok = :ranch.stop_listener(Mailmaid.SMTP.ServerExample)
    end
  end

  def active_once(socket, transport) do
    transport.setopts(socket, [{:active, :once}])
  end

  def send_and_wait(socket, transport, payload) do
    transport.send(socket, payload)
    transport.recv(socket, 0, 1000)
  end

  def receive_auth_lines(socket, transport, acc \\ false) do
    case transport.recv(socket, 0, 1000) do
      {:ok, "250-AUTH" <> _rest = line} ->
        receive_auth_lines(socket, transport, true)

      {:ok, "250-" <> _rest = line} ->
        receive_auth_lines(socket, transport, acc)

      {:ok, "250 AUTH" <> _rest} ->
        true

      {:ok, "250 " <> _rest} ->
        acc

      {:ok, _} ->
        :error
    end
  end

  def wait_for_banner(socket, transport) do
    assert {:ok, "220 mailmaid.localhost " <> _} = transport.recv(socket, 0, 1000)
  end

  describe "EHLO" do
    test "it accepts a hostname" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250-mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")

        assert true == receive_auth_lines(socket, transport)
      end)
    end

    test "will error if not given a hostname" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "501 Syntax Error: EHLO hostname\r\n"} = send_and_wait(socket, transport, "EHLO\r\n")
      end)
    end
  end

  describe "HELO" do
    test "it accepts a hostname" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250 mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "HELO somehost.com\r\n")
      end)
    end

    test "will error if not given a hostname" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "501 Syntax Error: HELO hostname\r\n"} = send_and_wait(socket, transport, "HELO\r\n")
      end)
    end
  end

  describe "AUTH" do
    test "will error if HELO or EHLO is not called first" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "503 ERROR: send EHLO first\r\n"} = send_and_wait(socket, transport, "AUTH\r\n")
      end)
    end
  end

  def perform_successful_login(socket, transport, username, password) do
    assert {:ok, "334 VXNlcm5hbWU6\r\n"} = send_and_wait(socket, transport, "AUTH LOGIN\r\n")
    assert {:ok, "334 UGFzc3dvcmQ6\r\n"} = send_and_wait(socket, transport, "#{Base.encode64(username)}\r\n")
    assert {:ok, "235 Authentication successful\r\n"} = send_and_wait(socket, transport, "#{Base.encode64(password)}\r\n")
  end

  def perform_unsuccessful_login(socket, transport, username, password) do
    assert {:ok, "334 VXNlcm5hbWU6\r\n"} = send_and_wait(socket, transport, "AUTH LOGIN\r\n")
    assert {:ok, "334 UGFzc3dvcmQ6\r\n"} = send_and_wait(socket, transport, "#{Base.encode64(username)}\r\n")
    assert {:ok, "535 Authentication failed\r\n"} = send_and_wait(socket, transport, "#{Base.encode64(password)}\r\n")
  end

  def ehlo_intro(socket, transport) do
    wait_for_banner(socket, transport)

    assert {:ok, "250-mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
    assert true == receive_auth_lines(socket, transport)
  end

  describe "AUTH LOGIN" do
    test "will accept an HELO before the AUTH" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250 mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "HELO somehost.com\r\n")
        assert {:ok, "502 ERROR: AUTH not implemented\r\n"} = send_and_wait(socket, transport, "AUTH LOGIN\r\n")
      end)
    end

    test "will accept an EHLO before the AUTH and successfully authneticate" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_successful_login(socket, transport, "username", "PaSSw0rd")
      end)
    end

    test "will accept an EHLO before the AUTH and unsuccessfully authneticate" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_unsuccessful_login(socket, transport, "username", "meh")
      end)
    end

    test "will accept an EHLO before the AUTH and unsuccessfully authneticate because malformed username" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "334 VXNlcm5hbWU6\r\n"} = send_and_wait(socket, transport, "AUTH LOGIN\r\n")
        assert {:ok, "501 Malformed LOGIN username\r\n"} = send_and_wait(socket, transport, "malf roem\r\n")
      end)
    end

    test "will accept an EHLO before the AUTH and unsuccessfully authneticate because malformed password" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "334 VXNlcm5hbWU6\r\n"} = send_and_wait(socket, transport, "AUTH LOGIN\r\n")
        assert {:ok, "334 UGFzc3dvcmQ6\r\n"} = send_and_wait(socket, transport, "#{Base.encode64("username")}\r\n")
        assert {:ok, "501 Malformed LOGIN password\r\n"} = send_and_wait(socket, transport, "pass word\r\n")
      end)
    end
  end

  def format_plain({username, password}) do
    Base.encode64("#{username}\0#{password}")
  end

  def format_plain({identity, username, password}) do
    Base.encode64("#{identity}\0#{username}\0#{password}")
  end

  def perform_successful_plain_inline(socket, transport, pl) do
    assert {:ok, "235 Authentication successful\r\n"} = send_and_wait(socket, transport, "AUTH PLAIN #{format_plain(pl)}\r\n")
  end

  def perform_unsuccessful_plain_inline(socket, transport, pl) do
    assert {:ok, "535 Authentication failed\r\n"} = send_and_wait(socket, transport, "AUTH PLAIN #{format_plain(pl)}\r\n")
  end

  def perform_successful_plain(socket, transport, pl) do
    assert {:ok, "334\r\n"} = send_and_wait(socket, transport, "AUTH PLAIN\r\n")
    assert {:ok, "235 Authentication successful\r\n"} = send_and_wait(socket, transport, "#{format_plain(pl)}\r\n")
  end

  def perform_unsuccessful_plain(socket, transport, pl) do
    assert {:ok, "334\r\n"} = send_and_wait(socket, transport, "AUTH PLAIN\r\n")
    assert {:ok, "535 Authentication failed\r\n"} = send_and_wait(socket, transport, "#{format_plain(pl)}\r\n")
  end

  describe "AUTH PLAIN" do
    test "will accept an HELO before the AUTH" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250 mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "HELO somehost.com\r\n")
        assert {:ok, "502 ERROR: AUTH not implemented\r\n"} = send_and_wait(socket, transport, "AUTH PLAIN\r\n")
      end)
    end

    test "will be successful given correct credentials [inline]" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_successful_plain_inline(socket, transport, {"username", "PaSSw0rd"})
      end)
    end

    test "will be successful given correct credentials [inline] (with identity)" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_successful_plain_inline(socket, transport, {"IAm User", "username", "PaSSw0rd"})
      end)
    end

    test "will be successful given correct credentials" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_successful_plain(socket, transport, {"username", "PaSSw0rd"})
      end)
    end

    test "will be successful given correct credentials (with identity)" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_successful_plain(socket, transport, {"IAm User", "username", "PaSSw0rd"})
      end)
    end

    test "will not be successful given a incorrect username [inline]" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_unsuccessful_plain_inline(socket, transport, {"IAm User", "nottheuser", "PaSSw0rd"})
      end)
    end

    test "will not be successful given a incorrect password [inline]" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_unsuccessful_plain_inline(socket, transport, {"IAm User", "username", "notthepassword"})
      end)
    end

    test "will not be successful given both incorrect username and password [inline]" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_unsuccessful_plain_inline(socket, transport, {"IAm User", "nottheuser", "notthepassword"})
      end)
    end

    test "will not be successful given a incorrect username" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_unsuccessful_plain(socket, transport, {"IAm User", "nottheuser", "PaSSw0rd"})
      end)
    end

    test "will not be successful given a incorrect password" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_unsuccessful_plain(socket, transport, {"IAm User", "username", "notthepassword"})
      end)
    end

    test "will not be successful given both incorrect username and password" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_unsuccessful_plain(socket, transport, {"IAm User", "nottheuser", "notthepassword"})
      end)
    end

    test "will error given malformed login [inline] (unencoded)" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "501 Malformed AUTH PLAIN\r\n"} = send_and_wait(socket, transport, "AUTH PLAIN username\0PaSSw0rd\r\n")
      end)
    end

    test "will error given malformed login [inline] (missing password)" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "501 Malformed AUTH PLAIN\r\n"} = send_and_wait(socket, transport, "AUTH PLAIN #{Base.encode64("username")}\r\n")
      end)
    end

    test "will error given malformed login (unencoded)" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "334\r\n"} = send_and_wait(socket, transport, "AUTH PLAIN\r\n")
        assert {:ok, "501 Malformed AUTH PLAIN\r\n"} = send_and_wait(socket, transport, "username\0PaSSw0rd\r\n")
      end)
    end

    test "will error given malformed login (missing password)" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "334\r\n"} = send_and_wait(socket, transport, "AUTH PLAIN\r\n")
        assert {:ok, "501 Malformed AUTH PLAIN\r\n"} = send_and_wait(socket, transport, "#{Base.encode64("username")}\r\n")
      end)
    end
  end

  def format_cram_md5({username, password}) do
    Base.encode64("#{username} #{password}")
  end

  def perform_cram_md5(socket, transport, {username, password}) do
    assert {:ok, "334 " <> seed64} = send_and_wait(socket, transport, "AUTH CRAM-MD5\r\n")
    seed64 = String.trim_trailing(seed64, "\r\n")
    {:ok, seed} = Base.decode64(seed64)
    digest = Mailmaid.SMTP.Auth.CramMD5.compute_digest(password, seed)
    send_and_wait(socket, transport, "#{format_cram_md5({username, digest})}\r\n")
  end

  def perform_successful_cram_md5(socket, transport, pl) do
    assert {:ok, "235 Authentication successful\r\n"} = perform_cram_md5(socket, transport, pl)
  end

  def perform_unsuccessful_cram_md5(socket, transport, pl) do
    assert {:ok, "535 Authentication failed\r\n"} = perform_cram_md5(socket, transport, pl)
  end

  describe "AUTH CRAM-MD5" do
    test "will accept an HELO before the AUTH" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250 mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "HELO somehost.com\r\n")
        assert {:ok, "502 ERROR: AUTH not implemented\r\n"} = send_and_wait(socket, transport, "AUTH CRAM-MD5\r\n")
      end)
    end

    test "will be successful given correct credentials" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_successful_cram_md5(socket, transport, {"username", "PaSSw0rd"})
      end)
    end

    test "will not be successful given a incorrect username" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_unsuccessful_cram_md5(socket, transport, {"nottheuser", "PaSSw0rd"})
      end)
    end

    test "will not be successful given a incorrect password" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_unsuccessful_cram_md5(socket, transport, {"username", "notthepassword"})
      end)
    end

    test "will not be successful given both incorrect username and password" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        perform_unsuccessful_cram_md5(socket, transport, {"nottheuser", "notthepassword"})
      end)
    end
  end

  def receive_starttls_lines(socket, transport, acc \\ false) do
    case transport.recv(socket, 0, 1000) do
      {:ok, "250-STARTTLS" <> _rest = line} ->
        receive_starttls_lines(socket, transport, true)

      {:ok, "250-" <> _rest = line} ->
        receive_starttls_lines(socket, transport, acc)

      {:ok, "250 STARTTLS" <> _rest} ->
        true

      {:ok, "250 " <> _rest} ->
        acc

      {:ok, _} ->
        :error
    end
  end

  describe "STARTTLS" do
    @tls_server_options [
      ssl_options: [{:keyfile, "test/fixtures/server.key"}, {:certfile, "test/fixtures/server.crt"}]
    ]

    test "EHLO response includes STARTTLS" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)
        assert {:ok, "250-mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert true == receive_starttls_lines(socket, transport)
      end, @tls_server_options)
    end

    test "STARTTLS does a SSL handshake" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)
        assert {:ok, "250-mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert true == receive_starttls_lines(socket, transport)
        assert {:ok, "220 " <> _} = send_and_wait(socket, transport, "STARTTLS\r\n")
        transport = :ranch_ssl
        assert {:ok, _socket} = :ssl.connect(socket, [])
      end, @tls_server_options)
    end

    test "After STARTTLS, EHLO doesn't report STARTTLS" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)
        assert {:ok, "250-mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert true == receive_starttls_lines(socket, transport)
        assert {:ok, "220 " <> _} = send_and_wait(socket, transport, "STARTTLS\r\n")
        transport = :ranch_ssl
        assert {:ok, socket} = :ssl.connect(socket, [])
        assert {:ok, "250-mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert false == receive_starttls_lines(socket, transport)
      end, @tls_server_options)
    end

    test "After STARTTLS, re-negotiating STARTTLS is an error" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)
        assert {:ok, "250-mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert true == receive_starttls_lines(socket, transport)
        assert {:ok, "220 " <> _} = send_and_wait(socket, transport, "STARTTLS\r\n")
        transport = :ranch_ssl
        assert {:ok, socket} = :ssl.connect(socket, [])
        assert {:ok, "250-mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert false == receive_starttls_lines(socket, transport)
        assert {:ok, "500 " <> _} = send_and_wait(socket, transport, "STARTTLS\r\n")
      end, @tls_server_options)
    end

    test "STARTTLS can't take any parameters" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)
        assert {:ok, "250-mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert true == receive_starttls_lines(socket, transport)
        assert {:ok, "501 " <> _} = send_and_wait(socket, transport, "STARTTLS foo\r\n")
      end, @tls_server_options)
    end

    test "After STARTTLS, message is received by server" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)
        assert {:ok, "250-mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert true == receive_starttls_lines(socket, transport)
        assert {:ok, "220 " <> _} = send_and_wait(socket, transport, "STARTTLS\r\n")
        transport = :ranch_ssl
        assert {:ok, socket} = :ssl.connect(socket, [])
        assert {:ok, "250-mailmaid.localhost\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert false == receive_starttls_lines(socket, transport)
        assert {:ok, "250 " <> _} = send_and_wait(socket, transport, "MAIL FROM: <user@somehost.com>\r\n")
        assert {:ok, "250 " <> _} = send_and_wait(socket, transport, "RCPT TO: <user@otherhost.com>\r\n")
        assert {:ok, "354 " <> _} = send_and_wait(socket, transport, "DATA\r\n")
        transport.send(socket, "Subject: tls message\r\n")
        transport.send(socket, "To: <user@otherhost.com>\r\n")
        transport.send(socket, "From: <user@somehost.com>\r\n")
        transport.send(socket, "\r\n")
        transport.send(socket, "message body")
        transport.send(socket, "\r\n.\r\n")
        assert {:ok, "250 " <> _} = transport.recv(socket, 0, 1000)
      end, @tls_server_options)
    end
  end

  describe "MAIL FROM" do
    test "will error unless HELO or EHLO is called first" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "503 ERROR: send EHLO or HELO first\r\n"} = send_and_wait(socket, transport, "MAIL\r\n")
      end)
    end

    test "will error if MAIL command is missing parameters" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "501 Syntax Error: MAIL FROM:<address>\r\n"} = send_and_wait(socket, transport, "MAIL\r\n")
      end)
    end

    test "will accept a MAIL FROM command" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com>\r\n")
      end)
    end

    test "will accept a MAIL FROM command with extensions [SIZE]" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com> SIZE=1048576\r\n")
      end)
    end

    test "will accept a MAIL FROM command with extensions [BODY]" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com> BODY=BIN\r\n")
      end)
    end

    test "will accept a MAIL FROM command with extensions [other]" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com> X-SomeExtension\r\n")
      end)
    end

    test "will error given a blacklisted address" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "552 go away\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<badguy@blacklist.com>\r\n")
      end)
    end

    test "will error given a multiple MAIL commands" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com>\r\n")
        assert {:ok, "503 ERROR: Multiple MAIL command\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com>\r\n")
      end)
    end
  end

  describe "RCPT" do
    test "will error unless HELO or EHLO is called first" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "503 ERROR: send EHLO or HELO first\r\n"} = send_and_wait(socket, transport, "RCPT\r\n")
      end)
    end

    test "will error unless MAIL is called first" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "503 ERROR: send MAIL first\r\n"} = send_and_wait(socket, transport, "RCPT\r\n")
      end)
    end

    test "will error unless RCPT commands has parameters" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)
        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com>\r\n")

        assert {:ok, "501 Syntax Error: RCPT TO:<address>\r\n"} = send_and_wait(socket, transport, "RCPT\r\n")
      end)
    end

    test "will error given a RCPT command with parameters, but no address" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)
        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com>\r\n")

        assert {:ok, "501 Bad recipient address syntax\r\n"} = send_and_wait(socket, transport, "RCPT TO:<>\r\n")
      end)
    end

    test "will accept a RCPT command with parameters" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)
        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com>\r\n")
        assert {:ok, "250 Recipient OK\r\n"} = send_and_wait(socket, transport, "RCPT TO:<someone-else@example.com>\r\n")
      end)
    end

    test "will accept a RCPT command with parameters, but reject an address" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)
        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com>\r\n")

        assert {:ok, "550 No such recipient\r\n"} = send_and_wait(socket, transport, "RCPT TO:<nobody@example.com>\r\n")
      end)
    end

    test "will accept a RCPT command with parameters and extensions" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)
        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com>\r\n")
        assert {:ok, "250 Recipient OK\r\n"} = send_and_wait(socket, transport, "RCPT TO:<someone-else@example.com> EXT=value\r\n")
      end)
    end
  end

  describe "DATA" do
    test "will error unless HELO or EHLO is called first" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "503 ERROR: send EHLO or HELO first\r\n"} = send_and_wait(socket, transport, "DATA\r\n")
      end)
    end

    test "will error unless MAIL is called first" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)
        assert {:ok, "503 ERROR: need MAIL command\r\n"} = send_and_wait(socket, transport, "DATA\r\n")
      end)
    end

    test "will error unless RCPT is called first" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)
        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com>\r\n")
        assert {:ok, "503 ERROR: need RCPT command\r\n"} = send_and_wait(socket, transport, "DATA\r\n")
      end)
    end

    test "will start reading data" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)
        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com>\r\n")
        assert {:ok, "250 Recipient OK\r\n"} = send_and_wait(socket, transport, "RCPT TO:<someone-else@example.com>\r\n")
        assert {:ok, "354 enter mail, end with line containing only '.'\r\n"} = send_and_wait(socket, transport, "DATA\r\n")
      end)
    end

    test "will read data until ." do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)
        assert {:ok, "250 Sender OK\r\n"} = send_and_wait(socket, transport, "MAIL FROM:<someone@example.com>\r\n")
        assert {:ok, "250 Recipient OK\r\n"} = send_and_wait(socket, transport, "RCPT TO:<someone-else@example.com>\r\n")
        assert {:ok, "354 enter mail, end with line containing only '.'\r\n"} = send_and_wait(socket, transport, "DATA\r\n")

        :ok = transport.send(socket, "This is a multiline message\r\n")
        :ok = transport.send(socket, "So this should have like, plenty of messages\r\n")
        :ok = transport.send(socket, "The end is neigh\r\n")
        :ok = transport.send(socket, "\r\n")
        :ok = transport.send(socket, ".\r\n")

        assert {:ok, "250 queued as " <> _} = transport.recv(socket, 0, 5000)
      end)
    end
  end

  describe "RSET" do
    test "will reset" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "250 OK\r\n"} = send_and_wait(socket, transport, "RSET\r\n")
      end)
    end
  end

  describe "NOOP" do
    test "will do nothing" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "250 OK\r\n"} = send_and_wait(socket, transport, "NOOP\r\n")
      end)
    end
  end

  describe "QUIT" do
    test "will close the connection" do
      launch_server(fn socket, transport ->
        ehlo_intro(socket, transport)

        assert {:ok, "221 BYE\r\n"} = send_and_wait(socket, transport, "QUIT\r\n")
        assert {:error, :closed} = transport.recv(socket, 0, 1000)
      end)
    end
  end

  describe "VRFY" do
    test "will verify an address" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)
        assert {:ok, "252 VRFY disabled by policy, just send some mail\r\n"} = send_and_wait(socket, transport, "VRFY <someone@example.com>\r\n")
      end)
    end
  end
end
