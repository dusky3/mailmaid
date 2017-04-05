defmodule Mailmaid.SMTP.ServerExample do
  defmodule State do
    defstruct [options: []]

    @type t :: %__MODULE__{
      options: list
    }
  end

  @relay true

  @behaviour Mailmaid.SMTP.Server.Session

  def init(hostname, session_count, address, options) do
    :io.format("peer: ~p~n", [address])

    if session_count > 20 do
      :io.format("Connection limit exceeded~n")
      {:stop, :normal, ["421 ", hostname, " is too busy to accept mail right now"]}
    else
      banner = [hostname, " ESMTP Mailmaid.SMTP.ServerExample"]
      state = %State{options: options}
      {:ok, banner, state}
    end
  end

  def handle_HELO(<<"invalid">>, extensions, state) do
    {:error, "554 invalid hostname", state}
  end

  def handle_HELO(<<"trusted_host">>, extensions, state) do
    {:ok, state}
  end

  def handle_HELO(hostname, state) do
    :io.format("HELO from ~s~n", [hostname])
    {:ok, 655360, state}
  end

  def handle_EHLO(<<"invalid">>, extensions, state) do
    {:error, "554 invalid hostname", state}
  end

  def handle_EHLO(hostname, extensions, state) do
    :io.format("EHLO from ~s~n", [hostname])

    my_extensions = if :proplists.get_value(:auth, state.options, false) do
      extensions ++ [{"AUTH", "PLAIN LOGIN CRAM-MD5"}, {"STARTTLS", true}]
    else
      extensions
    end

    {:ok, my_extensions, state}
  end

  def handle_MAIL(<<"badguy@blacklist.com">>, state) do
    {:error, "552 go away", state}
  end

  def handle_MAIL(from, state) do
    :io.format("Mail from ~s~n", [from])
    {:ok, state}
  end

  def handle_MAIL_extension(<<"X-SomeExtension">> = extension, state) do
    :io.format("Mail from extension ~s~n", [extension])

    {:ok, state}
  end

  def handle_MAIL_extension(extension, state) do
    :io.format("Unknown MAIL FROM extension ~s~n", [extension])
    :error
  end

  def handle_RCPT(<<"nobody@example.com">>, state) do
    {:error, "550 No such recipient", state}
  end

  def handle_RCPT(to, state) do
    :io.format("Mail to ~s~n", [to])
    {:ok, state}
  end

  def handle_RCPT_extension(<<"X-SomeExtension">> =extension, state) do
    :io.format("Mail to extension ~s~n", [extension])
    {:ok, state}
  end

  def handle_RCPT_extension(extension, _state) do
    :io.format("Unknown RCPT TO extension ~s~n", [extension])
    :error
  end

  def handle_DATA(from, to, <<>>, state) do
    {:error, "552 Message too small", state}
  end

  def handle_DATA(from, to, data, state) do
    #reference = :lists.flatten([:io_lib.format("~2.16.0b", [x])])
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

  def handle_AUTH(type, <<"username">>, <<"PaSSw0rd">>, state) when type == :login or type == :plain do
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
    :io.format("TLS Started~n")
    state
  end

  def code_change(_old_vsn, state, _extra) do
    {:ok, state}
  end

  def terminate(reason, state) do
    {:ok, reason, state}
  end

  def relay(_, [], _), do: :ok

  def relay(from, [to | rest], data) do
    [_user, host] = String.split(to, "@")
    Mailmaid.SMTP.Client.send({from, [to], data}, [relay: host])
    relay(from, rest, data)
  end
end
