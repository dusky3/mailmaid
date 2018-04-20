require Logger

defmodule Mailmaid.SMTP.Client do
  alias Mailmaid.SMTP.Client.Connection
  alias Mailmaid.SMTP.Client.Commands

  @type email_item ::
    {from :: String.t, to :: String.t, body :: binary} |
    {id :: term, from :: String.t, to :: String.t, body :: binary}
  @type email_items :: [email_item]
  @type receipt_item :: {:ok | :error, id :: term, term}
  @type receipt_items :: [receipt_item]
  @type host_error :: {distance :: non_neg_integer, host :: String.t, error :: term}
  @type host_errors :: [host_error]

  @type client_options :: %{
    # Relay configuration
    procotol: :tcp | :ssl,
    relay: String.t,
    port: non_neg_integer,
    socket_options: list,
    connect_timeout: non_neg_integer,
    # should the client do a mail-exchange lookup
    use_mx_lookups: boolean,
    # if using the tcp protocol, will attempt to upgrade the connection using STARTTLS
    upgrade_to_tls: :never | :if_available | :always,
    # Should the AUTH command be used? options are :never | :if_available | :always
    # if :never, the AUTH command will never be called
    # if :if_available, the AUTH command will attempted, but if it fails, the process will continue
    # if :always, the AUTH command will be attemped, if it fails the process will aborted
    use_auth: :never | :if_available | :always,
    auth_preference: [String.t],
    username: String.t,
    password: String.t,
    # the client's hostname
    hostname: String.t,
    # how many times should the client attempt to deliver the mail?
    retries: non_neg_integer,
    # data = sends the DATA command
    # noop = sends a NOOP command instead
    action: :data | :noop,
  }

  # yeah... EHLO and HELO commands...
  defp introduce_yourself(socket, options) do
    hostname = to_string(options.hostname)
    case Commands.ehlo(socket, hostname) do
      {:ok, socket, messages} ->
        {_remote_hostname, extensions} = Commands.parse_extensions(messages)
        {:ok, socket, extensions}
      {:error, socket, {:permanent_failure, _messages}} ->
        Commands.helo(socket, hostname)
    end
  end

  defp try_starttls(socket, extensions, %{upgrade_to_tls: :never}) do
    {:ok, socket, extensions}
  end

  defp try_starttls(socket, extensions, %{procotol: :tcp} = options) do
    if extensions["STARTTLS"] do
      case Commands.starttls(socket) do
        {:ok, _socket, _messages} ->
          introduce_yourself(socket, options)
        {:error, _socket, {:upgrade_error, _}} = err -> err
        {:error, socket, _reason} = err ->
          case options.use_auth do
            :always -> err
            :if_available -> {:ok, socket, extensions}
          end
      end
    else
      case options.use_auth do
        :always -> {:error, socket, {:starttls_unavailable, []}}
        :if_available -> {:ok, socket, extensions}
      end
    end
  end

  defp try_starttls(socket, extensions, %{procotol: :ssl}) do
    {:ok, socket, extensions}
  end

  defp try_auth(socket, _extensions, %{use_auth: :never}) do
    {:ok, socket, []}
  end

  defp try_auth(socket, extensions, options) do
    case extensions["AUTH"] do
      # the server supports no form of AUTH
      nil ->
        {:error, socket, {:auth_disabled, []}}
      auth_types_str ->
        auth_types =
          auth_types_str
          |> String.split(" ")
          |> Enum.map(&String.trim/1)
          |> Enum.map(&String.upcase/1)
          |> Enum.uniq()

        Enum.reduce_while(options.auth_preference, {:error, socket, {:auth_unavailable, []}}, fn
          method, {_, socket, _} = acc ->
            if method in auth_types do
              case Commands.auth(socket, method, options.username, options.password) do
                {:ok, _socket, _messages} = res -> {:halt, res}
                {:error, _socket, _messages} = err -> {:cont, err}
              end
            else
              {:cont, acc}
            end
        end)
    end
    |> case do
      {:ok, _socket, _reason} = res -> res
      {:error, socket, _reason} = err ->
        case options.use_auth do
          :always -> err
          :if_available -> {:ok, socket, []}
        end
    end
  end

  defp set_recipients(socket, []) do
    {:ok, socket, []}
  end

  defp set_recipients(socket, [recipient | rest]) do
    case Commands.rcpt_to(socket, recipient) do
      {:ok, socket, _} -> set_recipients(socket, rest)
      {:error, _socket, _reason} = err -> err
    end
  end

  @spec try_smtp_session_sending(email_items, Commands.socket, map, map, receipt_items) :: {:ok, Commands.socket, receipt_items}
  defp try_smtp_session_sending([], socket, _extensions, _options, receipts) do
    {:ok, socket, Enum.reverse(receipts)}
  end

  defp try_smtp_session_sending([item | rest], socket, extensions, options, receipts) do
    # TODO: maybe reset before or after each message
    #{_, socket, _} = Commands.rset(socket)
    {id, from, to, body} = case item do
      {_id, _from, _to, _body} = res -> res
      {from, to, body} -> {nil, from, to, body}
    end
    {status, socket, msg} =
      with {:ok, socket, _} <- Commands.mail_from(socket, from),
           {:ok, socket, _} <- set_recipients(socket, to) do
        case options.action do
          :data -> Commands.data(socket, body)
          :noop -> Commands.noop(socket)
        end
      else
        {:error, _, _} = err -> err
      end
    try_smtp_session_sending(rest, socket, extensions, options, [{status, id, msg} | receipts])
  end

  defp try_smtp_session(host, emails, options) do
    with {:ok, socket, options, _messages} <- Connection.open(host, options),
         {:ok, socket, extensions} <- introduce_yourself(socket, options),
         {:ok, socket, extensions} <- try_starttls(socket, extensions, options),
         {:ok, socket, _messages} <- try_auth(socket, extensions, options) do
      try_smtp_session_sending(emails, socket, extensions, options, [])
    else
      {:error, socket, {kind, _} = reason} when kind in [:permanent_failure, :starttls_unavailable, :auth_unavailable] ->
        # normal errors/failures can be quitted
        Commands.quit(socket)
        {:error, reason}
      {:error, socket, {:upgrade_error, _} = reason} ->
        # upgrade failures end up bricking the connection, so simply closing it is the best option
        Connection.close(socket)
        {:error, reason}
      {:error, _} = err -> err
    end
  end

  defp try_smtp_sessions([], _emails, _options, errors) do
    {:error, {:no_more_hosts, Enum.reverse(errors)}}
  end

  defp try_smtp_sessions([{distance, host} | rest], emails, options, errors) do
    case try_smtp_session(host, emails, options) do
      {:ok, socket, receipts} ->
        Commands.quit(socket)
        {:ok, receipts}
      {:error, _, _} = err ->
        try_smtp_sessions(rest, emails, options, [{distance, host, err} | errors])
      {:error, _} = err ->
        try_smtp_sessions(rest, emails, options, [{distance, host, err} | errors])
    end
  end

  @spec default_options :: client_options
  def default_options() do
    %{
      procotol: :tcp,
      relay: nil,
      port: 25,
      socket_options: [],
      connect_timeout: 5000,
      use_mx_lookups: true,
      upgrade_to_tls: :never,
      use_auth: :if_available,
      auth_preference: ["CRAM-MD5", "LOGIN", "PLAIN"],
      username: nil,
      password: nil,
      hostname: to_string(:smtp_util.guess_FQDN()),
      retries: 1,
      action: :data,
    }
  end

  @doc """
  Sends a list of emails to a relay server
  """
  @spec send_blocking(email_items, Keyword.t | map) :: {:ok, receipt_items} | {:error, {:no_more_hosts, host_errors}} | {:error, term}
  def send_blocking(emails, user_options) do
    options = Map.merge(default_options(), Enum.into(user_options, %{}))
    relay_domain = options[:relay]

    hosts =
      if options.use_mx_lookups do
        :smtp_util.mxlookup(relay_domain)
      else
        []
      end
      |> case do
        [] -> [{0, relay_domain}]
        mx_records -> mx_records
      end

    Logger.debug [
      "send_blocking",
      " relay=", inspect(relay_domain),
      " hosts=", inspect(hosts),
      " protocol=", inspect(options[:protocol]),
      " port=", inspect(options[:port]),
      " upgrade_to_tls=", inspect(options[:upgrade_to_tls]),
      " use_auth=", inspect(options[:use_auth]),
      " hostname=", inspect(options[:hostname]),
    ]
    try_smtp_sessions(hosts, List.wrap(emails), options, [])
  end

  @spec send_blocking_noop(email_items, Keyword.t | map) :: term
  def send_blocking_noop(emails, user_options) do
    send_blocking(emails, Enum.into(user_options, %{}) |> Map.put(:action, :noop))
  end

  def process_options(options) do
    Logger.warn "process_options is deprecated, this function is kept for compatibility with the LegacyClient"
    options =
      options
      |> Enum.into([])
      |> Mailmaid.SMTP.LegacyClient.process_options()
    protocol = if options[:ssl] do :ssl else :tcp end
    options
    |> Keyword.drop([:auth, :tls, :ssl])
    |> Keyword.merge(
      transport: options[:transport] || :mm4,
      upgrade_to_tls: options[:upgrade_to_tls] || options[:tls],
      use_auth: options[:use_auth] || options[:auth],
      procotol: options[:procotol] || protocol
    )
  end
end
