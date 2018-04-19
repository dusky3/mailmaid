alias Mailmaid.SMTP.Client.Connection, as: CC
alias Mailmaid.SMTP.Client.Commands, as: CMD

defmodule Mailmaid.SMTP.Client.NewClientTest do
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
      ]}
      | additional_options
    ]
    {:ok, pid} = Mailmaid.SMTP.Server.start_link(Mailmaid.SMTP.ServerExample, [server_options])
    {:ok, %{server_pid: pid, hostname: hostname, port: server_options[:port]}}
  end

  defmodule ConnectionTest do
    use ExUnit.Case

    setup options do
      on_exit(fn ->
        :ok = :ranch.stop_listener(Mailmaid.SMTP.ServerExample)
      end)
      Mailmaid.SMTP.Client.NewClientTest.setup_server(options)
    end

    describe "open" do
      test "it will open a new smtp connection to server", %{hostname: hostname, port: port} do
        assert {:ok, socket, {:tcp, hostname, ^port}, [banner]} = CC.open(hostname, port: port)

        assert 'mailmaid.localhost' == hostname
        assert "220 mailmaid.localhost ESMTP Mailmaid.SMTP.ServerExample\r\n" == banner
        :ok = CC.close(socket)
      end
    end
  end

  defmodule CommandsTest do
    use ExUnit.Case

    setup options do
      protocol = options[:protocol] || :tcp
      {:ok, %{hostname: hostname, port: port} = options} = Mailmaid.SMTP.Client.NewClientTest.setup_server(options)
      {:ok, socket, {^protocol, _hostname, ^port}, [banner]} = CC.open(hostname, port: port)
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
    end

    describe "HELO" do
      test "will send an HELO command", %{socket: socket} do
        assert {:ok, _socket, messages} = CMD.helo(socket, "client-test.localhost")
        assert [
          "250 mailmaid.localhost\r\n",
        ] == messages
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
  end
end
