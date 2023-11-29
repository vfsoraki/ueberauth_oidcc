defmodule UeberauthOidcc.RawInfo do
  @moduledoc """
  Struct for the data passed to the callback as `s:Ueberauth.Auth.Extra` `raw_info`.
  """
  @type t() :: %__MODULE__{
          opts: map,
          claims: string_map(),
          userinfo: string_map() | nil
        }
  @type string_map() :: %{optional(String.t()) => String.t() | number | string_map() | nil}

  @derive {Inspect, except: [:opts], optional: [:userinfo]}

  defstruct opts: %{},
            claims: %{},
            userinfo: nil
end
