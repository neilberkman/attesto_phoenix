defmodule AttestoPhoenix.RouterTest do
  @moduledoc """
  Tests for the `attesto_routes/1` router macro: the mounted route table, the
  optional `:prefix` and `:registration` toggles, and `:pipeline` wiring.
  """

  use ExUnit.Case, async: true

  alias AttestoPhoenix.Controller.AuthorizeController
  alias AttestoPhoenix.Controller.OpenIDConfigurationController
  alias AttestoPhoenix.Controller.PARController
  alias AttestoPhoenix.Controller.UserinfoController

  defmodule DefaultRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes()
    end
  end

  defmodule RegistrationRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(registration: true)
    end
  end

  defmodule PrefixedRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    scope "/" do
      attesto_routes(prefix: "/auth", registration: true)
    end
  end

  defmodule PipelineRouter do
    use Phoenix.Router
    use AttestoPhoenix.Router

    pipeline :oauth_server do
      plug :accepts, ["json"]
    end

    scope "/" do
      attesto_routes(pipeline: :oauth_server)
    end
  end

  # `Phoenix.Router.routes/1` returns a list of route maps; find the one for a
  # given verb + path so a test can assert presence or inspect its pipeline.
  defp find_route(router, method, path) do
    router
    |> Phoenix.Router.routes()
    |> Enum.find(fn r -> r.verb == method and r.path == path end)
  end

  describe "attesto_routes/1" do
    test "mounts the discovery document at the well-known path" do
      assert find_route(DefaultRouter, :get, "/.well-known/oauth-authorization-server")
    end

    test "mounts the OpenID Provider configuration at the well-known path" do
      route = find_route(DefaultRouter, :get, "/.well-known/openid-configuration")
      assert route
      assert route.plug == OpenIDConfigurationController
    end

    test "mounts the JWKS document at the well-known path" do
      assert find_route(DefaultRouter, :get, "/.well-known/jwks.json")
    end

    test "mounts the authorization endpoint at both GET and POST (OIDC Core §3.1.2.1)" do
      get_route = find_route(DefaultRouter, :get, "/oauth/authorize")
      post_route = find_route(DefaultRouter, :post, "/oauth/authorize")

      assert get_route
      assert post_route
      assert get_route.plug == AuthorizeController
      assert post_route.plug == AuthorizeController
    end

    test "mounts the token endpoint" do
      assert find_route(DefaultRouter, :post, "/oauth/token")
    end

    test "mounts the pushed authorization request endpoint" do
      route = find_route(DefaultRouter, :post, "/oauth/par")
      assert route
      assert route.plug == PARController
    end

    test "mounts the UserInfo endpoint at both GET and POST (OIDC Core §5.3.1)" do
      get_route = find_route(DefaultRouter, :get, "/oauth/userinfo")
      post_route = find_route(DefaultRouter, :post, "/oauth/userinfo")

      assert get_route
      assert post_route
      assert get_route.plug == UserinfoController
      assert post_route.plug == UserinfoController
    end

    test "mounts the revocation endpoint" do
      assert find_route(DefaultRouter, :post, "/oauth/revoke")
    end

    test "does not mount registration by default" do
      refute find_route(DefaultRouter, :post, "/oauth/register")
      refute find_route(DefaultRouter, :delete, "/oauth/register/:client_id")
    end

    test "mounts registration when enabled" do
      assert find_route(RegistrationRouter, :post, "/oauth/register")
      assert find_route(RegistrationRouter, :delete, "/oauth/register/:client_id")
    end

    test "applies the prefix to the oauth endpoints" do
      assert find_route(PrefixedRouter, :get, "/auth/oauth/authorize")
      assert find_route(PrefixedRouter, :post, "/auth/oauth/authorize")
      assert find_route(PrefixedRouter, :post, "/auth/oauth/token")
      assert find_route(PrefixedRouter, :post, "/auth/oauth/par")
      assert find_route(PrefixedRouter, :post, "/auth/oauth/register")
      assert find_route(PrefixedRouter, :delete, "/auth/oauth/register/:client_id")
      assert find_route(PrefixedRouter, :get, "/auth/oauth/userinfo")
      assert find_route(PrefixedRouter, :post, "/auth/oauth/userinfo")
    end

    test "keeps the well-known documents at the root even with a prefix" do
      assert find_route(PrefixedRouter, :get, "/.well-known/oauth-authorization-server")
      assert find_route(PrefixedRouter, :get, "/.well-known/openid-configuration")
      assert find_route(PrefixedRouter, :get, "/.well-known/jwks.json")
    end

    test "with a pipeline pipes the mounted routes through the named pipeline" do
      info = Phoenix.Router.route_info(PipelineRouter, "POST", "/oauth/token", "localhost")
      assert info.pipe_through == [:oauth_server]
    end
  end
end
