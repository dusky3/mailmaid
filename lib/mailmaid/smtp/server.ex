defmodule Mailmaid.SMTP.Server do
  defmacro __using__(_opts) do
    quote do
      @behaviour Mailmaid.SMTP.Protocol
    end
  end

  @moduledoc """
  Options
  """
  alias :ranch, as: Ranch

  @type ubyte_t :: {0..255}
  @type int16_t :: {0..0xFFFF}
  @type ipv4_t :: {ubyte_t, ubyte_t, ubyte_t, ubyte_t}
  @type ipv6_t :: {int16_t, int16_t, int16_t, int16_t, int16_t, int16_t}
  @type listener_config :: [
    {:address, ipv4_t | ipv6_t},
    {:family, :inet | :inet6},
    {:hostname, String.t},
    {:port, non_neg_integer},
    {:sessionoptions, Keyword.t},
    {:protocol, :tcp},
    {:ssl_options, [
      {:keyfile, String.t},
      {:certfile, String.t},
    ]},
  ]

  @doc """
  Starts a new SMTP server listener

  Args:
  * `session_module` - the callback module and name of the listener
  * `listeners` - a list of keyword lists. For now just wrap the args in a list.
  """
  @spec start_link(session_module :: atom, listeners :: [listener_config]) :: {:ok, pid} | {:error, term}
  def start_link(session_module, [listener_options]) do
    num_acceptors = 256
    transport_opts = [
      {:port, Keyword.get(listener_options, :port, 2525)},
      Keyword.get(listener_options, :family, :inet)
    ]
    opts = [
      session_module: session_module,
      hostname: Keyword.get(listener_options, :hostname, :smtp_util.guess_FQDN()),
      address: Keyword.get(listener_options, :address, {0, 0, 0, 0}),
      session_options: Keyword.get(listener_options, :sessionoptions, []),
      tls: false,
      ssl_options: Keyword.get(listener_options, :ssl_options, []),
    ]
    {transport, transport_opts} = case Keyword.get(listener_options, :protocol, :tcp) do
      :tcp -> {:ranch_tcp, transport_opts}
      :ssl ->
        more_options = Keyword.get(listener_options, :ssl_options)
        {:ranch_ssl, transport_opts ++ more_options}
    end
    Ranch.start_listener(session_module, num_acceptors, transport, transport_opts, Mailmaid.SMTP.Protocol, opts)
  end
end
