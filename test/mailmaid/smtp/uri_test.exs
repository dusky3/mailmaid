defmodule Mailmaid.SMTP.URITest do
  use ExUnit.Case, async: true
  alias Mailmaid.SMTP
  doctest SMTP.URI

  describe "parse" do
    test "parses a smtp client/server uri without auth" do
      config = SMTP.URI.parse("smtp://domain.devl:4525") |> Enum.into(%{})
      assert %{port: 4525, relay: "domain.devl", auth: :never, tls: :never} == config
    end

    test "parses a smtp client/server uri without tls" do
      config = SMTP.URI.parse("smtp://user:pass@domain.devl:3525") |> Enum.into(%{})
      assert %{port: 3525, relay: "domain.devl", username: "user", password: "pass", auth: :if_available, tls: :never} == config
    end

    test "parses a smtp client/server uri with optional tls" do
      config = SMTP.URI.parse("smtp+s://user:pass@domain.devl:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.devl", username: "user", password: "pass", auth: :if_available, tls: :if_available} == config
    end

    test "parses a smtp client/server uri with mandatory tls" do
      config = SMTP.URI.parse("smtps://user:pass@domain.devl:2525") |> Enum.into(%{})
      assert %{port: 2525, relay: "domain.devl", username: "user", password: "pass", auth: :if_available, tls: :always} == config
    end
  end
end
