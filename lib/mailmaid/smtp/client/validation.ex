defmodule Mailmaid.SMTP.Client.Validation do
  @spec check_auth_options({requirement :: atom, term}, term) :: :ok | {:error, term}
  def check_auth_options({:always, _}, options) do
    case :proplists.is_defined(:username, options) and :proplists.is_defined(:password, options) do
      false -> {:error, :no_credentials}
      true -> :ok
    end
  end

  def check_auth_options({_, _}, _options) do
    :ok
  end

  def check_options(options) do
    case :proplists.get_value(:relay, options) do
      :undefined ->
        {:error, :no_relay}

      _ ->
        case :proplists.get_value(:auth, options) do
          atom when is_atom(atom) ->
            check_auth_options({atom, []}, options)

          {_, _} = auth ->
            check_auth_options(auth, options)

          _ -> :ok
        end
    end
  end
end
