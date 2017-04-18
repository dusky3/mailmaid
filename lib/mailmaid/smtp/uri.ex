defmodule Mailmaid.SMTP.URI do
  @moduledoc """
  Handles special uris in mailer config
  """
  def user_credentials_from_uri(%{userinfo: u} = _uri) when is_nil(u) or u == "", do: nil
  def user_credentials_from_uri(%{userinfo: userinfo} = _uri) when is_binary(userinfo) do
    case String.split(userinfo, ":") do
      [username, password] ->
        {username, password}

      [username] ->
        {username, username}
    end
  end

  def determine_tls_from_scheme("smtps"), do: :always
  def determine_tls_from_scheme("mm4"), do: :always
  def determine_tls_from_scheme("smtp+s"), do: :if_available
  def determine_tls_from_scheme("mm4+s"), do: :if_available
  def determine_tls_from_scheme(_other), do: :never

  @spec update_mailer_config_from_uri(uri :: URI.t, config :: Keyword.t) :: Keyword.t
  def update_mailer_config_from_uri(uri, config \\ []) do
    tls = determine_tls_from_scheme(uri.scheme)
    case user_credentials_from_uri(uri) do
      {username, password} ->
        [
          {:relay, uri.host},
          {:port, uri.port},
          {:username, username},
          {:password, password},
          {:tls, tls},
          {:auth, :if_available}
          | config
        ]

      nil ->
        [
          {:relay, uri.host},
          {:port, uri.port},
          {:tls, tls},
          {:auth, :never}
          | config
        ]
    end
  end

  def parse(uri, config \\ []) do
    uri
    |> Elixir.URI.decode()
    |> Elixir.URI.parse()
    |> update_mailer_config_from_uri(config)
  end

  def process_mailer_config(config) do
    case config[:url] do
      nil -> config
      url ->
        config = Keyword.delete(config, :url)
        parse(url, config)
    end
  end
end
