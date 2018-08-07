defmodule Mailmaid.SMTP.ServerTest do
  use ExUnit.Case, aynsc: false

  describe "child_spec/1" do
    test "creates a supervisor child spec" do

    end
  end

  describe "supervisor child_spec" do
    @dummy_email {"test-email", "john.doe@example.com", ["sally.sue@example.com"], "HELLO"}

    test "can start a tcp listener from it's child spec" do
      assert {:ok, pid} = start_supervised({
        Mailmaid.SMTP.Server,
        session_module: Mailmaid.SMTP.ServerExample,
        listeners: [
          [
            port: 12525
          ]
        ],
        process_options: [
          ref: Mailmaid.SMTP.ServerExample.TCP
        ]
      }, id: :tcp_example_server)

      assert {:ok, [{:ok, "test-email", ["250 OK\r\n"]}]} = Mailmaid.SMTP.Client.send_blocking_noop(@dummy_email, relay: "localhost", port: 12525)

      :ok = stop_supervised(:tcp_example_server)
    end

    test "can start a ssl listener from it's child spec" do
      assert {:ok, pid} = start_supervised({
        Mailmaid.SMTP.Server,
        session_module: Mailmaid.SMTP.ServerExample,
        listeners: [
          [
            port: 12465,
            protocol: :ssl,
            ssl_options: [
              keyfile: "test/fixtures/server.key",
              certfile: "test/fixtures/server.crt",
            ]
          ]
        ],
        process_options: [
          ref: Mailmaid.SMTP.ServerExample.SSL
        ]
      }, id: :ssl_example_server)

      assert {:ok, [{:ok, "test-email", ["250 OK\r\n"]}]} = Mailmaid.SMTP.Client.send_blocking_noop(
        @dummy_email,
        protocol: :ssl,
        relay: "localhost",
        port: 12465
      )

      :ok = stop_supervised(:ssl_example_server)
    end
  end
end
