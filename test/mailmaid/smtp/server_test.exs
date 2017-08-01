defmodule Mailmaid.SMTP.ServerTest do
  use ExUnit.Case

  def launch_server(cb) do
    {:ok, _pid} = Mailmaid.SMTP.Server.start_link(Mailmaid.SMTP.ServerExample, [
      [
        hostname: "mailmaid.devl",
        port: 9876,
        sessionoptions: [
          callbackoptions: [auth: true]
        ]
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
    assert {:ok, "220 mailmaid.devl " <> _} = transport.recv(socket, 0, 1000)
  end

  describe "EHLO" do
    test "it accepts a hostname" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250-mailmaid.devl\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")

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

        assert {:ok, "250 mailmaid.devl\r\n"} = send_and_wait(socket, transport, "HELO somehost.com\r\n")
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

    assert {:ok, "250-mailmaid.devl\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
    assert true == receive_auth_lines(socket, transport)
  end

  describe "AUTH LOGIN" do
    test "will accept an HELO before the AUTH" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250 mailmaid.devl\r\n"} = send_and_wait(socket, transport, "HELO somehost.com\r\n")
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

        assert {:ok, "250 mailmaid.devl\r\n"} = send_and_wait(socket, transport, "HELO somehost.com\r\n")
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

        assert {:ok, "250 mailmaid.devl\r\n"} = send_and_wait(socket, transport, "HELO somehost.com\r\n")
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

end
