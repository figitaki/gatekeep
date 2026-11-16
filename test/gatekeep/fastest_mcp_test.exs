defmodule Gatekeep.FastestMCPTest do
  use Gatekeep.Case

  setup do
    name = "gatekeep-test-#{System.unique_integer([:positive])}"

    FastestMCP.server(name,
      protected_resource:
        Gatekeep.FastestMCP.protected_resource(TestAuth, TestAuth.mcp(),
          required_scopes: ["notes:read"]
        )
    )
    |> FastestMCP.add_auth(Gatekeep.FastestMCP,
      gatekeep: TestAuth,
      resource: TestAuth.mcp(),
      scopes: ["notes:read"]
    )
    |> FastestMCP.add_tool("whoami", fn _args, ctx -> ctx.principal end)
    |> FastestMCP.start_server!()

    %{server: name, client: TestClient.new()}
  end

  defp call(server, auth_input),
    do: FastestMCP.call_tool(server, "whoami", %{}, auth_input: auth_input)

  test "a Gatekeep token reaches the tool as its subject and client", ctx do
    %{"access_token" => access} = sign_in(ctx.client)

    assert {:ok, %{"sub" => "user:1", "client_id" => client_id}} =
             call(ctx.server, %{"authorization" => "Bearer " <> access})

    assert client_id == ctx.client.client_id
  end

  test "the assign from Gatekeep.Plug.Resource is used as is", ctx do
    %{"access_token" => access} = sign_in(ctx.client)

    {:ok, token} =
      Gatekeep.Token.authenticate(TestAuth.config(), TestAuth.mcp(), %{
        authorization: "Bearer " <> access,
        dpop: [],
        method: "POST",
        path: "/mcp"
      })

    assert {:ok, %{"sub" => "user:1"}} =
             call(ctx.server, %{"assigns" => %{"gatekeep_token" => token}})
  end

  test "no token, another resource's token, and a token without the scope are refused", ctx do
    assert {:error, %{code: :unauthorized}} = call(ctx.server, %{})

    %{"access_token" => other} =
      sign_in(ctx.client, %{"resource" => TestAuth.other(), "scope" => nil})

    assert {:error, %{code: :unauthorized}} =
             call(ctx.server, %{"authorization" => "Bearer " <> other})

    %{"access_token" => write_only} = sign_in(ctx.client, %{"scope" => "notes:write"})

    assert {:error, %{code: :forbidden}} =
             call(ctx.server, %{"authorization" => "Bearer " <> write_only})
  end

  test "an assign checked for another resource is refused", ctx do
    %{"access_token" => other} =
      sign_in(ctx.client, %{"resource" => TestAuth.other(), "scope" => nil})

    {:ok, token} =
      Gatekeep.Token.authenticate(TestAuth.config(), TestAuth.other(), %{
        authorization: "Bearer " <> other,
        dpop: [],
        method: "GET",
        path: "/other"
      })

    assert {:error, %{code: :unauthorized}} =
             call(ctx.server, %{"assigns" => %{"gatekeep_token" => token}})
  end
end
