defmodule Mailmaid.SMTP.URI do
  @moduledoc """
  Handles special uris in mailer config
  """

  @spec user_credentials_from_uri(map) :: {String.t | nil, String.t, String.t | nil}
  def user_credentials_from_uri(%{userinfo: u} = _uri) when is_nil(u) or u == "", do: nil
  def user_credentials_from_uri(%{userinfo: userinfo} = _uri) when is_binary(userinfo) do
    case String.split(userinfo, ":") do
      [identity, username, password] ->
        {identity, username, password}

      [username, password] ->
        {nil, username, password}

      [username] ->
        {nil, username, nil}
    end
  end

  @spec parse_legacy(String.t, Keyword.t) :: Keyword.t
  def parse_legacy(uri, config \\ []) do
    uri =
      uri
      |> Elixir.URI.decode()
      |> Elixir.URI.parse()

    {tls, ssl} = case uri.scheme do
      "smtps" -> {:never, true}
      "smtp+s" -> {:if_available, false}
      "mm4s" -> {:never, true}
      "mm4+s" -> {:if_available, false}
      _other -> {:never, false}
    end

    options = [
      {:scheme, uri.scheme},
      {:relay, uri.host},
      {:tls, tls},
      {:ssl, ssl}
    ]

    options = if uri.port do
      [{:port, uri.port} | options]
    else
      options
    end

    options = case user_credentials_from_uri(uri) do
      {_, username, password} ->
        [
          {:username, username},
          {:password, password},
          {:auth, :always}
          | options
        ]

      nil ->
        [{:auth, :never} | options]
    end

    Keyword.merge(options, config)
  end

  def process_legacy_mailer_config(config) when is_list(config) do
    case config[:url] do
      nil -> config
      url ->
        config = Keyword.delete(config, :url)
        parse_legacy(url, config)
    end
  end

  @spec parse(String.t, Keyword.t) :: map
  def parse(uri_s, config \\ []) do
    uri =
      uri_s
      |> Elixir.URI.decode()
      |> Elixir.URI.parse()

    options = %{
      original_uri: uri_s,
      transport: :mm4,
      protocol: :tcp,
      relay: uri.host,
      port: uri.port,
      upgrade_to_tls: :never,
      use_auth: :never,
      identity: nil,
      username: nil,
      password: nil,
    }

    options = case uri.scheme do
      "mm4" -> %{options | transport: :mm4}
      "mm4s" -> %{options | transport: :mm4, protocol: :ssl}
      "mm4+s" -> %{options | transport: :mm4, upgrade_to_tls: :if_available}
      "smtp" -> %{options | transport: :mm4}
      "smtps" -> %{options | transport: :mm4, protocol: :ssl}
      "smtp+s" -> %{options | transport: :mm4, upgrade_to_tls: :if_available}
      "http" -> %{options | transport: :http}
      "https" -> %{options | transport: :http, protocol: :ssl}
    end

    options = case user_credentials_from_uri(uri) do
      {identity, username, password} ->
        %{options | use_auth: :always, identity: identity, username: username, password: password}

      _ -> options
    end

    Enum.into(config, options)
  end
end
