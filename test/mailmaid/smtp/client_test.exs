require Logger
alias Mailmaid.SMTP.Client
alias Client.Connection, as: CC
alias Client.Commands, as: CMD

defmodule Mailmaid.SMTP.ClientTest do
  use ExUnit.Case, async: false

  def setup_server(options) do
    port = options[:port] || 9876
    hostname = "mailmaid.localhost"
    additional_options =
      options
      |> Map.take([:protocol, :ssl_options])
      |> Enum.into([])

    server_options = [
      {:hostname, hostname},
      {:port, port},
      {:sessionoptions, [
        callbackoptions: [auth: true]
      ]},
      {:ssl_options,
        [
          {:keyfile, "test/fixtures/server.key"},
          {:certfile, "test/fixtures/server.crt"}
        ]
      }
      | additional_options
    ]
    Logger.debug ["Staring Server ", "hostname=", server_options[:hostname], " port=", inspect(server_options[:port]), " protocol=", inspect(server_options[:protocol])]
    {:ok, pid} = Mailmaid.SMTP.Server.start_link(Mailmaid.SMTP.ServerExample, [server_options])
    {:ok, Map.merge(options, %{server_pid: pid, hostname: hostname, port: server_options[:port]})}
  end

  setup options do
    on_exit(fn ->
      :ok = :ranch.stop_listener(Mailmaid.SMTP.ServerExample)
    end)
    Mailmaid.SMTP.ClientTest.setup_server(options)
  end

  describe "send_blocking" do
    test "will send an mms message over tcp", %{hostname: hostname, port: port} do
      email = {"john.doe@example.com", ["sally.sue@example.com", "sally.sue2@example.com"], "Hello, World"}
      assert {:ok, receipts} = Client.send_blocking(email,
        use_auth: :always,
        username: "username",
        password: "PaSSw0rd",
        upgrade_to_tls: :never,
        relay: hostname,
        port: port,
        protocol: :tcp,
        hostname: "mailmaid-client.localhost"
      )

      assert [{:ok, nil, ["250 queued as Accepted\r\n"]}] == receipts
    end

    @tag protocol: :ssl
    test "will send an mms message over ssl", %{hostname: hostname, port: port} do
      email = {"john.doe@example.com", ["sally.sue@example.com", "sally.sue2@example.com"], "Hello, World"}
      assert {:ok, receipts} = Client.send_blocking(email,
        use_auth: :always,
        username: "username",
        password: "PaSSw0rd",
        upgrade_to_tls: :never,
        relay: hostname,
        port: port,
        protocol: :ssl,
        hostname: "mailmaid-client.localhost"
      )

      assert [{:ok, nil, ["250 queued as Accepted\r\n"]}] == receipts
    end
  end
end

defmodule Mailmaid.SMTP.Client.ConnectionTest do
  use ExUnit.Case, async: false

  setup options do
    on_exit(fn ->
      :ok = :ranch.stop_listener(Mailmaid.SMTP.ServerExample)
    end)
    Mailmaid.SMTP.ClientTest.setup_server(options)
  end

  describe "open tcp connection" do
    test "it will open a new smtp connection to server", %{hostname: hostname, port: port} do
      assert {:ok, socket, {:tcp, hostname, ^port}, [banner]} = CC.open(hostname, port: port)

      assert 'mailmaid.localhost' == hostname
      assert "220 mailmaid.localhost ESMTP Mailmaid.SMTP.ServerExample\r\n" == banner
      :ok = CC.close(socket)
    end
  end

  describe "open ssl/tls connection" do
    @tag protocol: :ssl
    test "it will open a new smtp connection to server", %{hostname: hostname, port: port} do
      assert {:ok, socket, {:ssl, hostname, ^port}, [banner]} = CC.open(hostname, port: port, protocol: :ssl)

      assert 'mailmaid.localhost' == hostname
      assert "220 mailmaid.localhost ESMTP Mailmaid.SMTP.ServerExample\r\n" == banner
      :ok = CC.close(socket)
    end
  end
end

defmodule Mailmaid.SMTP.Client.CommandsUtilTest do
  use ExUnit.Case, async: false

  describe "parse_extensions" do
    test "will parse a list of EHLO extensions" do
      extensions = [
        "250-mailmaid.localhost\r\n",
        "250-SIZE 10485670\r\n",
        "250-8BITMIME\r\n",
        "250-PIPELINING\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5\r\n",
        "250 STARTTLS\r\n",
      ]
      assert {"mailmaid.localhost", parsed_extensions} = CMD.parse_extensions(extensions)

      assert %{
        "8BITMIME" => true,
        "AUTH" => "PLAIN LOGIN CRAM-MD5",
        "PIPELINING" => true,
        "SIZE" => "10485670",
        "STARTTLS" => true
      } == parsed_extensions
    end
  end
end

defmodule Mailmaid.SMTP.Client.CommandsTest do
  use ExUnit.Case, async: false

  setup options do
    protocol = options[:protocol] || :tcp
    {:ok, %{hostname: hostname, port: port} = options} = Mailmaid.SMTP.ClientTest.setup_server(options)
    {:ok, socket, {^protocol, _hostname, ^port}, [banner]} = CC.open(hostname, port: port, protocol: protocol)
    on_exit(fn ->
      :ok = CC.close(socket)
      :ok = :ranch.stop_listener(Mailmaid.SMTP.ServerExample)
    end)
    {:ok, Map.merge(options, %{socket: socket, banner: banner})}
  end

  describe "EHLO" do
    test "will send an EHLO command", %{socket: socket} do
      assert {:ok, _socket, features} = CMD.ehlo(socket, "client-test.localhost")
      assert [
        "250-mailmaid.localhost\r\n",
        "250-SIZE 10485670\r\n",
        "250-8BITMIME\r\n",
        "250-PIPELINING\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5\r\n",
        "250 STARTTLS\r\n",
      ] == features
    end

    test "will handle errors", %{socket: socket} do
      assert {:error, _socket, {:permanent_failure, messages}} = CMD.ehlo(socket, "invalid")

      assert [
        "554 invalid hostname\r\n"
      ] == messages
    end

    @tag protocol: :ssl
    test "will not include STARTTLS for a TLS connection", %{socket: socket} do
      assert {:ok, _socket, features} = CMD.ehlo(socket, "client-test.localhost")
      assert [
        "250-mailmaid.localhost\r\n",
        "250-SIZE 10485670\r\n",
        "250-8BITMIME\r\n",
        "250-PIPELINING\r\n",
        "250 AUTH PLAIN LOGIN CRAM-MD5\r\n",
      ] == features
    end
  end

  describe "HELO" do
    test "will send an HELO command", %{socket: socket} do
      assert {:ok, _socket, messages} = CMD.helo(socket, "client-test.localhost")
      assert [
        "250 mailmaid.localhost\r\n",
      ] == messages
    end

    test "will handle errors", %{socket: socket} do
      assert {:error, _socket, {:permanent_failure, messages}} = CMD.helo(socket, "invalid")

      assert [
        "554 invalid hostname\r\n"
      ] == messages
    end
  end

  describe "STARTTLS" do
    setup %{socket: socket} = tags do
      {:ok, socket, _features} = CMD.ehlo(socket, "client-test.localhost")
      {:ok, %{tags | socket: socket}}
    end

    test "will start a TLS connection", %{socket: socket} do
      assert {:ok, _ssl_socket, messages} = CMD.starttls(socket)

      assert [] == messages
    end
  end

  describe "AUTH" do
    setup %{socket: socket} = tags do
      {:ok, socket, _features} = CMD.ehlo(socket, "client-test.localhost")
      {:ok, %{tags | socket: socket}}
    end

    test "will send an AUTH PLAIN command", %{socket: socket} do
      assert {:ok, _socket, messages} = CMD.auth(socket, "PLAIN", "username", "PaSSw0rd")
      assert [
        "235 Authentication successful\r\n"
      ] = messages
    end

    test "when invalid username is given for AUTH PLAIN", %{socket: socket} do
      assert {:error, _socket, {:auth_error, messages}} = CMD.auth(socket, "PLAIN", "nottheuser", "PaSSw0rd")
      assert ["535 Authentication failed\r\n"] == messages
    end

    test "will send an AUTH LOGIN command", %{socket: socket} do
      assert {:ok, _socket, messages} = CMD.auth(socket, "LOGIN", "username", "PaSSw0rd")
      assert [
        "235 Authentication successful\r\n"
      ] = messages
    end

    test "when invalid username is given for AUTH LOGIN", %{socket: socket} do
      assert {:error, _socket, {:auth_error, messages}} = CMD.auth(socket, "LOGIN", "nottheuser", "PaSSw0rd")
      assert ["535 Authentication failed\r\n"] == messages
    end

    test "will send an AUTH CRAM-MD5 command", %{socket: socket} do
      assert {:ok, _socket, messages} = CMD.auth(socket, "CRAM-MD5", "username", "PaSSw0rd")
      assert [
        "235 Authentication successful\r\n"
      ] = messages
    end

    test "when invalid username is given for AUTH CRAM-MD5", %{socket: socket} do
      assert {:error, _socket, {:auth_error, messages}} = CMD.auth(socket, "CRAM-MD5", "nottheuser", "PaSSw0rd")
      assert ["535 Authentication failed\r\n"] == messages
    end
  end

  describe "VRFY" do
    test "will handle VRFY response", %{socket: socket} do
      assert {:ok, _socket, messages} = CMD.vrfy(socket, "someuser")

      assert ["250 someuser@" <> _rest] = messages
    end
  end

  describe "NOOP" do
    test "will handle NOOP response", %{socket: socket} do
      assert {:ok, _socket, messages} = CMD.noop(socket)

      assert ["250 OK\r\n"] == messages
    end
  end

  describe "RSET" do
    test "will handle RSET response", %{socket: socket} do
      assert {:ok, _socket, messages} = CMD.rset(socket)

      assert ["250 OK\r\n"] == messages
    end
  end

  describe "MAIL" do
    setup %{socket: socket} = tags do
      {:ok, socket, _features} = CMD.ehlo(socket, "client-test.localhost")
      {:ok, %{tags | socket: socket}}
    end

    test "will send a MAIL FROM command", %{socket: socket} do
      assert {:ok, _socket, messages} = CMD.mail_from(socket, "john.doe@example.com")

      assert ["250 Sender OK\r\n"] == messages
    end

    test "will handle errors", %{socket: socket} do
      assert {:error, _socket, {:permanent_failure, messages}} = CMD.mail_from(socket, "badguy@blacklist.com")

      assert ["552 go away\r\n"] == messages
    end
  end

  describe "RCPT" do
    setup %{socket: socket} = tags do
      {:ok, socket, _features} = CMD.ehlo(socket, "client-test.localhost")
      {:ok, socket, _messages} = CMD.mail_from(socket, "john.doe@example.com")
      {:ok, %{tags | socket: socket}}
    end

    test "will send a RCPT TO command", %{socket: socket} do
      assert {:ok, _socket, messages} = CMD.rcpt_to(socket, "sally.sue@example.com")

      assert ["250 Recipient OK\r\n"] == messages
    end

    test "will handle errors", %{socket: socket} do
      assert {:error, _socket, {:permanent_failure, messages}} = CMD.rcpt_to(socket, "nobody@example.com")
      assert ["550 No such recipient\r\n"] == messages
    end
  end

  describe "DATA" do
    setup %{socket: socket} = tags do
      {:ok, socket, _features} = CMD.ehlo(socket, "client-test.localhost")
      {:ok, socket, _messages} = CMD.mail_from(socket, "john.doe@example.com")
      {:ok, socket, _messages} = CMD.rcpt_to(socket, "sally.sue@example.com")
      {:ok, %{tags | socket: socket}}
    end

    test "will send a DATA command", %{socket: socket} do
      assert {:ok, _socket, messages} = CMD.data(socket, "Hello, World")

      assert ["250 queued as Accepted\r\n"] == messages
    end

    test "will handle errors", %{socket: socket} do
      assert {:error, _socket, {:permanent_failure, messages}} = CMD.data(socket, "")

      assert ["552 Message too small\r\n"] == messages
    end
  end

  describe "QUIT" do
    test "will handle noop response", %{socket: socket} do
      assert {:ok, _socket, messages} = CMD.quit(socket)

      assert ["221 BYE\r\n"] == messages
    end
  end

  describe "full stack" do
    @tag protocol: :ssl
    test "common commands for a session (ssl)", %{socket: socket} do
      assert {:ok, _socket, _messages} = CMD.noop(socket)
      assert {:ok, _socket, _messages} = CMD.ehlo(socket, "ssl-test.localhost")
      assert {:ok, _socket, _messages} = CMD.auth(socket, "LOGIN", "username", "PaSSw0rd")
      assert {:ok, _socket, _messages} = CMD.mail_from(socket, "john.doe@example.com")
      assert {:ok, _socket, _messages} = CMD.rcpt_to(socket, "sally.sue@example.com")
      assert {:ok, _socket, _messages} = CMD.data(socket, "Hello, World")
      assert {:ok, _socket, _messages} = CMD.rset(socket)
      assert {:ok, _socket, _messages} = CMD.quit(socket)
    end
  end
end

