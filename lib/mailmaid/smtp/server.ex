defmodule Mailmaid.SMTP.Server do
  defmacro __using__(_opts) do
    quote do
      @behaviour Mailmaid.SMTP.Server.Session
    end
  end

  def start_link(session_module, [args]) do
    num_acceptors = 256
    transport_opts = [
      port: Keyword.get(args, :port, 2525)
    ]
    opts = [
      session_module: session_module,
      hostname: Keyword.get(args, :hostname, :smtp_util.guess_FQDN()),
      address: Keyword.get(args, :address, {0, 0, 0, 0}),
      session_options: Keyword.get(args, :sessionoptions, []),
      tls: Keyword.get(args, :tls, false),
    ]
    :ranch.start_listener(session_module, num_acceptors, :ranch_tcp, transport_opts, Mailmaid.SMTP.Protocol, opts)
  end
end
