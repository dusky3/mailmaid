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
      assert %{port: 3525, relay: "domain.localhost", username: "user", password: "pass", auth: :if_available, ssl: false, tls: :never, scheme: "smtp"} == config
    end

    test "parses a smtp client/server uri with optional tls" do
      config = SMTP.URI.parse_legacy("smtp+s://user:pass@domain.localhost:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.localhost", username: "user", password: "pass", auth: :if_available, ssl: false, tls: :if_available, scheme: "smtp+s"} == config
    end

    test "parses a smtp client/server uri with mandatory tls" do
      config = SMTP.URI.parse_legacy("smtps://user:pass@domain.localhost:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.localhost", username: "user", password: "pass", auth: :if_available, ssl: true, tls: :always, scheme: "smtps"} == config
    end

    test "parses a mm4 client/server uri without auth" do
      config = SMTP.URI.parse_legacy("mm4://domain.localhost:4525") |> Enum.into(%{})
      assert %{port: 4525, relay: "domain.localhost", auth: :never, tls: :never, ssl: false, scheme: "mm4"} == config
    end

    test "parses a mm4 client/server uri without tls" do
      config = SMTP.URI.parse_legacy("mm4://user:pass@domain.localhost:3525") |> Enum.into(%{})
      assert %{port: 3525, relay: "domain.localhost", username: "user", password: "pass", auth: :if_available, ssl: false, tls: :never, scheme: "mm4"} == config
    end

    test "parses a mm4 client/server uri with optional tls" do
      config = SMTP.URI.parse_legacy("mm4+s://user:pass@domain.localhost:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.localhost", username: "user", password: "pass", auth: :if_available, ssl: false, tls: :if_available, scheme: "mm4+s"} == config
    end

    test "parses a mm4 client/server uri with mandatory tls" do
      config = SMTP.URI.parse_legacy("mm4s://user:pass@domain.localhost:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.localhost", username: "user", password: "pass", auth: :if_available, ssl: true, tls: :always, scheme: "mm4s"} == config
    end
  end
end
