require Logger

defmodule Mailmaid.SMTP.ServerExample do
  defmodule State do
    defstruct [options: []]

    @type t :: %__MODULE__{
      options: list
    }
  end

  use Mailmaid.SMTP.Server

  def init(hostname, session_count, address, options) do
    Logger.info ["Peer: ", inspect(address)]

    if session_count > 20 do
      Logger.error "Connecting limit exceeded"
      {:stop, :normal, ["421 ", hostname, " is too busy to accept mail right now"]}
    else
      banner = [hostname, " ESMTP Mailmaid.SMTP.ServerExample"]
      state = %State{options: options}
      {:ok, banner, state}
    end
  end

  def handle_HELO(<<"invalid">>, state) do
    {:error, "554 invalid hostname", state}
  end

  def handle_HELO(<<"trusted_host">>, state) do
    {:ok, state}
  end

  def handle_HELO(hostname, state) do
    IO.inspect hostname
    Logger.info ["HELO from ", hostname]
    {:ok, 655360, state}
  end

  def handle_EHLO(<<"invalid">>, _extensions, state) do
    {:error, "554 invalid hostname", state}
  end

  def handle_EHLO(hostname, extensions, state) do
    Logger.info ["EHLO from ", hostname]

    my_extensions = if Keyword.get(state.options, :auth, false) do
      extensions ++ [{"AUTH", "PLAIN LOGIN CRAM-MD5"}, {"STARTTLS", true}]
    else
      extensions
    end

    {:ok, my_extensions, state}
  end

  def handle_MAIL("badguy@blacklist.com", state) do
    {:error, "552 go away", state}
  end

  def handle_MAIL(from, state) do
    Logger.info ["MAIL FROM ", from]
    {:ok, state}
  end

  def handle_MAIL_extension("X-SomeExtension" = extension, state) do
    Logger.info ["MAIL FROM extension", extension]

    {:ok, state}
  end

  def handle_MAIL_extension(extension, state) do
    Logger.warn ["Unknown MAIL FROM extension", extension]
    :error
  end

  def handle_RCPT(<<"nobody@example.com">>, state) do
    {:error, "550 No such recipient", state}
  end

  def handle_RCPT(to, state) do
    Logger.info ["RCPT TO ", to]
    {:ok, state}
  end

  def handle_RCPT_extension(<<"X-SomeExtension">> = extension, state) do
    Logger.warn ["RCPT TO extension ", extension]
    {:ok, state}
  end

  def handle_RCPT_extension(extension, _state) do
    Logger.warn ["Unknown RCPT TO extension ", extension]
    :error
  end

  def handle_DATA(_from, _to, <<>>, state) do
    {:error, "552 Message too small", state}
  end

  def handle_DATA(_from, _to, _data, state) do
    #IO.inspect {:handle_DATA, from, to, data}
    #reference = :lists.flatten([:io_lib.format("~2.16.0b", [x])])
    {:ok, "Accepted", state}
  end

  def handle_RSET(state), do: state

  def handle_VRFY(<<"someuser">>, state) do
    {:ok, "someuser@#{:smtp_util.guess_FQDN()}", state}
  end

  def handle_VRFY(_address, state) do
    {:error, "252 VRFY disabled by policy, just send some mail", state}
  end

  def handle_other(verb, _args, state) do
    {["500 Error: command not recognized : '", verb, "'"], state}
  end

  def handle_AUTH(type, <<"username">>, <<"PaSSw0rd">>, state) when type in [:login, :plain] do
    {:ok, state}
  end

  def handle_AUTH(:"cram-md5", <<"username">>, {digest, seed}, state) do
    case :smtp_util.compute_cram_digest(<<"PaSSw0rd">>, seed) do
      ^digest -> {:ok, state}
      _ -> :error
    end
  end

  def handle_AUTH(_type, _username, _password, _state) do
    :error
  end

  def handle_STARTTLS(state) do
    Logger.info("TLS Started")
    state
  end

  def code_change(_old_vsn, state, _extra) do
    {:ok, state}
  end

  def terminate(reason, state) do
    {:ok, reason, state}
  end

  #def relay(_, [], _), do: :ok

  #def relay(from, [to | rest], data) do
  #  [_user, host] = String.split(to, "@")
  #  Mailmaid.SMTP.Client.send({from, [to], data}, [relay: host])
  #  relay(from, rest, data)
  #end
end
