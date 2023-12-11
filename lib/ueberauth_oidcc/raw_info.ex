defmodule UeberauthOidcc.RawInfo do
  @moduledoc """
  Struct for the data passed to the callback as the `raw_info` in  `Ueberauth.Auth.Extra`.
  """
  @type t() :: %__MODULE__{
          opts: map,
          claims: string_map(),
          userinfo: string_map() | nil,
          introspection: map() | nil
        }
  @type string_map() :: %{optional(String.t()) => String.t() | number | string_map() | nil}

  @derive {Inspect, except: [:opts], optional: [:userinfo, :introspection]}

  defstruct opts: %{},
            claims: %{},
            userinfo: nil,
            introspection: nil
end
