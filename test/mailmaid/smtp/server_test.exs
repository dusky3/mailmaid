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

  def perform_successful_login(socket, transport, username, password) do
    assert {:ok, "334 VXNlcm5hbWU6\r\n"} = send_and_wait(socket, transport, "AUTH LOGIN\r\n")
    assert {:ok, "334 UGFzc3dvcmQ6\r\n"} = send_and_wait(socket, transport, "#{Base.encode64(username)}\r\n")
    assert {:ok, "235 Authentication successful.\r\n"} = send_and_wait(socket, transport, "#{Base.encode64(password)}\r\n")
  end

  def perform_unsuccessful_login(socket, transport, username, password) do
    assert {:ok, "334 VXNlcm5hbWU6\r\n"} = send_and_wait(socket, transport, "AUTH LOGIN\r\n")
    assert {:ok, "334 UGFzc3dvcmQ6\r\n"} = send_and_wait(socket, transport, "#{Base.encode64(username)}\r\n")
    assert {:ok, "535 Authentication failed.\r\n"} = send_and_wait(socket, transport, "#{Base.encode64(password)}\r\n")
  end

  describe "AUTH" do
    test "will error if HELO or EHLO is not called first" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "503 ERROR: send EHLO or HELO first\r\n"} = send_and_wait(socket, transport, "AUTH\r\n")
      end)
    end

    test "will accept an HELO before the AUTH" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250 mailmaid.devl\r\n"} = send_and_wait(socket, transport, "HELO somehost.com\r\n")
        assert {:ok, "502 ERROR: AUTH not implemented\r\n"} = send_and_wait(socket, transport, "AUTH LOGIN\r\n")
      end)
    end

    test "will accept an EHLO before the AUTH LOGIN and successfully authneticate" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250-mailmaid.devl\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert true == receive_auth_lines(socket, transport)

        perform_successful_login(socket, transport, "username", "PaSSw0rd")
      end)
    end

    test "will accept an EHLO before the AUTH LOGIN and unsuccessfully authneticate" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250-mailmaid.devl\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert true == receive_auth_lines(socket, transport)

        perform_unsuccessful_login(socket, transport, "username", "meh")
      end)
    end

    test "will accept an EHLO before the AUTH LOGIN and unsuccessfully authneticate because malformed username" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250-mailmaid.devl\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert true == receive_auth_lines(socket, transport)

        assert {:ok, "334 VXNlcm5hbWU6\r\n"} = send_and_wait(socket, transport, "AUTH LOGIN\r\n")
        assert {:ok, "501 Malformed LOGIN username\r\n"} = send_and_wait(socket, transport, "malf roem\r\n")
      end)
    end

    test "will accept an EHLO before the AUTH LOGIN and unsuccessfully authneticate because malformed password" do
      launch_server(fn socket, transport ->
        wait_for_banner(socket, transport)

        assert {:ok, "250-mailmaid.devl\r\n"} = send_and_wait(socket, transport, "EHLO somehost.com\r\n")
        assert true == receive_auth_lines(socket, transport)

        assert {:ok, "334 VXNlcm5hbWU6\r\n"} = send_and_wait(socket, transport, "AUTH LOGIN\r\n")
        assert {:ok, "334 UGFzc3dvcmQ6\r\n"} = send_and_wait(socket, transport, "#{Base.encode64("username")}\r\n")
        assert {:ok, "501 Malformed LOGIN password\r\n"} = send_and_wait(socket, transport, "pass word\r\n")
      end)
    end
  end
end
