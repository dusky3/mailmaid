defmodule Mailmaid.SMTP.URITest do
  use ExUnit.Case, async: true
  alias Mailmaid.SMTP
  doctest SMTP.URI

  describe "parse" do
    test "parses a smtp client/server uri without auth" do
      config = SMTP.URI.parse("smtp://domain.devl:4525") |> Enum.into(%{})
      assert %{port: 4525, relay: "domain.devl", auth: :never, tls: :never, scheme: "smtp"} == config
    end

    test "parses a smtp client/server uri without tls" do
      config = SMTP.URI.parse("smtp://user:pass@domain.devl:3525") |> Enum.into(%{})
      assert %{port: 3525, relay: "domain.devl", username: "user", password: "pass", auth: :if_available, tls: :never, scheme: "smtp"} == config
    end

    test "parses a smtp client/server uri with optional tls" do
      config = SMTP.URI.parse("smtp+s://user:pass@domain.devl:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.devl", username: "user", password: "pass", auth: :if_available, tls: :if_available, scheme: "smtp+s"} == config
    end

    test "parses a smtp client/server uri with mandatory tls" do
      config = SMTP.URI.parse("smtps://user:pass@domain.devl:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.devl", username: "user", password: "pass", auth: :if_available, tls: :always, scheme: "smtps"} == config
    end

    test "parses a mm4 client/server uri without auth" do
      config = SMTP.URI.parse("mm4://domain.devl:4525") |> Enum.into(%{})
      assert %{port: 4525, relay: "domain.devl", auth: :never, tls: :never, scheme: "mm4"} == config
    end

    test "parses a mm4 client/server uri without tls" do
      config = SMTP.URI.parse("mm4://user:pass@domain.devl:3525") |> Enum.into(%{})
      assert %{port: 3525, relay: "domain.devl", username: "user", password: "pass", auth: :if_available, tls: :never, scheme: "mm4"} == config
    end

    test "parses a mm4 client/server uri with optional tls" do
      config = SMTP.URI.parse("mm4+s://user:pass@domain.devl:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.devl", username: "user", password: "pass", auth: :if_available, tls: :if_available, scheme: "mm4+s"} == config
    end

    test "parses a mm4 client/server uri with mandatory tls" do
      config = SMTP.URI.parse("mm4s://user:pass@domain.devl:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.devl", username: "user", password: "pass", auth: :if_available, tls: :always, scheme: "mm4s"} == config
    end
  end
end
