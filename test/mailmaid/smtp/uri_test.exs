defmodule Mailmaid.SMTP.URITest do
  use ExUnit.Case, async: true
  alias Mailmaid.SMTP
  doctest SMTP.URI

  describe "parse_legacy" do
    test "parses a smtp client/server uri without auth" do
      config = SMTP.URI.parse_legacy("smtp://domain.localhost:4525") |> Enum.into(%{})
      assert %{port: 4525, relay: "domain.localhost", auth: :never, ssl: false, tls: :never, scheme: "smtp"} == config
    end

    test "parses a smtp client/server uri without tls" do
      config = SMTP.URI.parse_legacy("smtp://user:pass@domain.localhost:3525") |> Enum.into(%{})
      assert %{port: 3525, relay: "domain.localhost", username: "user", password: "pass", auth: :always, ssl: false, tls: :never, scheme: "smtp"} == config
    end

    test "parses a smtp client/server uri with optional tls" do
      config = SMTP.URI.parse_legacy("smtp+s://user:pass@domain.localhost:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.localhost", username: "user", password: "pass", auth: :always, ssl: false, tls: :if_available, scheme: "smtp+s"} == config
    end

    test "parses a smtp client/server uri with mandatory tls" do
      config = SMTP.URI.parse_legacy("smtps://user:pass@domain.localhost:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.localhost", username: "user", password: "pass", auth: :always, ssl: true, tls: :never, scheme: "smtps"} == config
    end

    test "parses a mm4 client/server uri without auth" do
      config = SMTP.URI.parse_legacy("mm4://domain.localhost:4525") |> Enum.into(%{})
      assert %{port: 4525, relay: "domain.localhost", auth: :never, tls: :never, ssl: false, scheme: "mm4"} == config
    end

    test "parses a mm4 client/server uri without tls" do
      config = SMTP.URI.parse_legacy("mm4://user:pass@domain.localhost:3525") |> Enum.into(%{})
      assert %{port: 3525, relay: "domain.localhost", username: "user", password: "pass", auth: :always, ssl: false, tls: :never, scheme: "mm4"} == config
    end

    test "parses a mm4 client/server uri with optional tls" do
      config = SMTP.URI.parse_legacy("mm4+s://user:pass@domain.localhost:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.localhost", username: "user", password: "pass", auth: :always, ssl: false, tls: :if_available, scheme: "mm4+s"} == config
    end

    test "parses a mm4 client/server uri with mandatory tls" do
      config = SMTP.URI.parse_legacy("mm4s://user:pass@domain.localhost:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.localhost", username: "user", password: "pass", auth: :always, ssl: true, tls: :never, scheme: "mm4s"} == config
    end
  end

  describe "parse" do
    for transport <- [:mm4, :smtp] do
      test "parses a #{transport} uri without auth" do
        config = SMTP.URI.parse("#{unquote(transport)}://example.com:2556")
        assert %{
          transport: :mm4,
          protocol: :tcp,
          relay: "example.com",
          port: 2556,
          upgrade_to_tls: :never,
          use_auth: :never,
        } = config
      end

      test "parses a #{transport}+s uri without auth" do
        config = SMTP.URI.parse("#{unquote(transport)}+s://example.com:2556")
        assert %{
          transport: :mm4,
          protocol: :tcp,
          relay: "example.com",
          port: 2556,
          upgrade_to_tls: :if_available,
          use_auth: :never,
        } = config
      end

      test "parses a #{transport}s uri without auth" do
        config = SMTP.URI.parse("#{unquote(transport)}s://example.com:2556")
        assert %{
          transport: :mm4,
          protocol: :ssl,
          relay: "example.com",
          port: 2556,
          upgrade_to_tls: :never,
          use_auth: :never,
        } = config
      end

      test "parses a #{transport} uri with auth" do
        config = SMTP.URI.parse("#{unquote(transport)}://user:pass@example.com:2556")
        assert %{
          transport: :mm4,
          protocol: :tcp,
          relay: "example.com",
          port: 2556,
          upgrade_to_tls: :never,
          use_auth: :always,
          identity: nil,
          username: "user",
          password: "pass",
        } = config
      end

      test "parses a #{transport} uri with auth and identity" do
        config = SMTP.URI.parse("#{unquote(transport)}://ident:user:pass@example.com:2556")
        assert %{
          transport: :mm4,
          protocol: :tcp,
          relay: "example.com",
          port: 2556,
          upgrade_to_tls: :never,
          use_auth: :always,
          identity: "ident",
          username: "user",
          password: "pass",
        } = config
      end

      test "parses a #{transport}+s uri with auth" do
        config = SMTP.URI.parse("#{unquote(transport)}+s://user:pass@example.com:2556")
        assert %{
          transport: :mm4,
          protocol: :tcp,
          relay: "example.com",
          port: 2556,
          upgrade_to_tls: :if_available,
          use_auth: :always,
          identity: nil,
          username: "user",
          password: "pass",
        } = config
      end

      test "parses a #{transport}s uri with auth" do
        config = SMTP.URI.parse("#{unquote(transport)}s://user:pass@example.com:2556")
        assert %{
          transport: :mm4,
          protocol: :ssl,
          relay: "example.com",
          port: 2556,
          upgrade_to_tls: :never,
          use_auth: :always,
          identity: nil,
          username: "user",
          password: "pass",
        } = config
      end
    end

    test "parses a http uri without auth" do
      uri = "http://example.com:2556"
      config = SMTP.URI.parse(uri)
        assert %{
          original_uri: ^uri,
          transport: :http,
          protocol: :tcp,
          relay: "example.com",
          port: 2556,
          upgrade_to_tls: :never,
          use_auth: :never,
          identity: nil,
          username: nil,
          password: nil,
        } = config
    end

    test "parses a https uri without auth" do
      uri = "https://example.com:2556"
      config = SMTP.URI.parse(uri)
        assert %{
          original_uri: ^uri,
          transport: :http,
          protocol: :ssl,
          relay: "example.com",
          port: 2556,
          upgrade_to_tls: :never,
          use_auth: :never,
          identity: nil,
          username: nil,
          password: nil,
        } = config
    end

    test "parses a http uri with auth" do
      uri = "http://user:pass@example.com:2556"
      config = SMTP.URI.parse(uri)
        assert %{
          original_uri: ^uri,
          transport: :http,
          protocol: :tcp,
          relay: "example.com",
          port: 2556,
          upgrade_to_tls: :never,
          use_auth: :always,
          identity: nil,
          username: "user",
          password: "pass",
        } = config
    end

    test "parses a https uri with auth" do
      uri = "https://user:pass@example.com:2556"
      config = SMTP.URI.parse(uri)
        assert %{
          original_uri: ^uri,
          transport: :http,
          protocol: :ssl,
          relay: "example.com",
          port: 2556,
          upgrade_to_tls: :never,
          use_auth: :always,
          identity: nil,
          username: "user",
          password: "pass",
        } = config
    end
  end
end
