# Mailmaid

Rewrite/Port of [gen_smtp](https://github.com/Vagabond/gen_smtp), using ranch as the listener as well as other changes.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `mailmaid` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:mailmaid, "~> 1.1.0"}]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/mailmaid](https://hexdocs.pm/mailmaid).

## Changelog

[Changelog can be found here](CHANGELOG.md)

## Usage

Mailmaid includes both a client and server implementation.

### Client

The interface is similar to `gen_smtp`

```elixir
config = [relay: "email.example.com", port: 25]

from = "john.doe@example.com"
recipient = "sally.sue@example.com"
body = "EMAIL_BODY_HERE"
email = {from, [recipient], body}

case Mailmaid.SMTP.Client.send_blocking(email, config) do
  {:ok, receipts} ->
    [{:ok, nil, receipt_lines}] = receipts
    # receipt_lines is the raw response from the server, including the status code
    # e.g. ["250 OK message accepted"] = receipt_lines
end
```

Multiple emails can be sent over the same connection

```elixir
config = [relay: "email.example.com", port: 25]

from = "john.doe@example.com"
recipients = ["sally.sue@example.com", "egg.bert@example.com"]
body = "EMAIL_BODY_HERE"
emails =
  Enum.map(recipients, fn recipient ->
    {from, [recipient], body}
  end)

case Mailmaid.SMTP.Client.send_blocking(emails, config) do
  {:ok, receipts} ->
    Enum.each(receipts, fn {:ok, nil, receipt_lines} ->
      ["250 OK message accepted"] = receipt_lines
    end)
end
```

When sending multiple emails, sometimes it's hard to tell which email which receipt belongs to, in this case, the emails can be assigned an id which will be included in the response.

```elixir
config = [relay: "email.example.com", port: 25]

from = "john.doe@example.com"
recipient = [{"sallys-email", "sally.sue@example.com"}, {2121, "egg.bert@example.com"}]
body = "EMAIL_BODY_HERE"
emails =
  Enum.map(recipients, fn {id, recipient} ->
    {id, from, [recipient], body}
  end)

case Mailmaid.SMTP.Client.send_blocking(emails, config) do
  {:ok, receipts} ->
    Enum.each(receipts, fn
      {:ok, "sallys-email", receipt_lines} ->
        # sally's email
        ["250 OK message accepted"] = receipt_lines
      {:ok, 2121, receipt_lines} ->
        # egg bert's email
        ["250 OK message accepted"] = receipt_lines
    end)
end
```

### Server

```elixir
defmodule MySMTPServer do
  # This will only set the behaviour module
  # start_link and all other behaviour functions must be implemented.
  use Mailmaid.SMTP.Server

  def child_spec(options) do
    Mailmaid.SMTP.Server.child_spec([{:session_module, __MODULE__} | options])
  end

  def start_link(options) do
    Mailmaid.SMTP.Server.start_link(__MODULE__, options[:listeners], options[:process_config])
  end

  # ... all other behaviour functions
end

```

## TODO

* Drop `gen_smtp` as a dependency, it's kept around for some modules, such as it's socket and utils.
