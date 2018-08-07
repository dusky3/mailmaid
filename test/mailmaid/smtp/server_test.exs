defmodule Mailmaid.SMTP.ServerTest do
  use ExUnit.Case, aynsc: false

  describe "child_spec/1" do
    test "creates a supervisor child spec" do

    end
  end

  describe "supervisor child_spec" do
    test "can be started from it's child spec" do
      assert {:ok, pid} = start_supervised({
        Mailmaid.SMTP.Server,
        session_module: Mailmaid.SMTP.ServerExample,
        listeners: [
          [
            port: 12345
          ]
        ]
      })

      :ok = stop_supervised(Mailmaid.SMTP.ServerExample)
    end
  end
end
