defmodule AttestoPhoenix.Schema.AuthorizationTest do
  use ExUnit.Case, async: true

  alias AttestoPhoenix.Schema.Authorization

  @now ~U[2024-01-01 00:00:00Z]
  @expires_unix DateTime.to_unix(~U[2024-01-01 00:01:00Z], :second)

  defp base_data do
    %{
      client_id: "client-123",
      subject: "subject-abc",
      scope: ["read", "write"],
      redirect_uri: "https://rp.example/cb",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      claims: %{"acr" => "phr"}
    }
  end

  defp base_record(data_overrides \\ %{}) do
    %{
      code_hash: "hash-of-the-code",
      data: Map.merge(base_data(), data_overrides),
      expires_at: @expires_unix
    }
  end

  describe "from_record/2" do
    test "produces a valid changeset spreading grant data across columns" do
      changeset = Authorization.from_record(base_record(), now: @now)

      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :code_hash) == "hash-of-the-code"
      assert Ecto.Changeset.get_change(changeset, :client_id) == "client-123"
      assert Ecto.Changeset.get_change(changeset, :subject) == "subject-abc"
      assert Ecto.Changeset.get_change(changeset, :scope) == ["read", "write"]
      assert Ecto.Changeset.get_change(changeset, :redirect_uri) == "https://rp.example/cb"
      assert Ecto.Changeset.get_change(changeset, :claims) == %{"acr" => "phr"}
    end

    test "carries the grant family id for descendant revocation" do
      changeset =
        base_record(%{family_id: "fam-abc"})
        |> Authorization.from_record(now: @now)

      assert changeset.valid?
      assert Ecto.Changeset.get_change(changeset, :family_id) == "fam-abc"
    end

    test "converts the unix expiry to a utc_datetime column" do
      changeset = Authorization.from_record(base_record(), now: @now)

      assert Ecto.Changeset.get_change(changeset, :expires_at) ==
               DateTime.from_unix!(@expires_unix, :second)
    end

    test "stamps inserted_at from the :now option, truncated to the second" do
      changeset =
        Authorization.from_record(base_record(), now: ~U[2024-01-01 00:00:00.999Z])

      assert Ecto.Changeset.get_change(changeset, :inserted_at) == @now
    end

    test "promotes a flat dpop_jkt into a cnf binding map (RFC 7800 / RFC 9449)" do
      changeset =
        base_record(%{dpop_jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"})
        |> Authorization.from_record(now: @now)

      assert Ecto.Changeset.get_change(changeset, :cnf) ==
               %{"jkt" => "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}
    end

    test "stores no cnf for an unbound code rather than an empty map" do
      changeset = Authorization.from_record(base_record(), now: @now)

      refute Ecto.Changeset.get_change(changeset, :cnf)
    end

    test "carries the OIDC nonce" do
      changeset =
        base_record(%{nonce: "n-0S6_WzA2Mj"})
        |> Authorization.from_record(now: @now)

      assert Ecto.Changeset.get_change(changeset, :nonce) == "n-0S6_WzA2Mj"
    end

    test "applies the :prefix option to the row" do
      changeset =
        Authorization.from_record(base_record(), now: @now, prefix: "auth")

      assert Ecto.get_meta(changeset.data, :prefix) == "auth"
    end

    test "defaults to no prefix" do
      changeset = Authorization.from_record(base_record(), now: @now)

      assert Ecto.get_meta(changeset.data, :prefix) == nil
    end

    test "fails closed when the code hash is absent" do
      record = base_record() |> Map.delete(:code_hash)
      changeset = Authorization.from_record(record, now: @now)

      refute changeset.valid?
      assert %{code_hash: ["can't be blank"]} = errors_on(changeset)
    end

    test "fails closed when the client_id is absent" do
      changeset =
        base_record()
        |> put_in([:data], Map.delete(base_data(), :client_id))
        |> Authorization.from_record(now: @now)

      refute changeset.valid?
      assert %{client_id: ["can't be blank"]} = errors_on(changeset)
    end

    test "fails closed when the redirect_uri is absent" do
      changeset =
        base_record()
        |> put_in([:data], Map.delete(base_data(), :redirect_uri))
        |> Authorization.from_record(now: @now)

      refute changeset.valid?
      assert %{redirect_uri: ["can't be blank"]} = errors_on(changeset)
    end

    test "accepts an absent PKCE challenge and stores no method (RFC 9700 confidential-client relaxation)" do
      # PKCE is optional at persistence: a confidential client the host exempted
      # from PKCE (Attesto.AuthorizationRequest's :require_pkce) issues a code
      # with no challenge. The changeset is valid and stores a NULL challenge AND
      # a NULL method - never a spurious "S256" for a challenge that is not there.
      data =
        base_data()
        |> Map.drop([:code_challenge, :code_challenge_method])

      changeset =
        base_record()
        |> put_in([:data], data)
        |> Authorization.from_record(now: @now)

      assert changeset.valid?
      assert Ecto.Changeset.get_field(changeset, :code_challenge) == nil
      assert Ecto.Changeset.get_field(changeset, :code_challenge_method) == nil
    end

    test "rejects a non-S256 code-challenge method (RFC 7636 §4.3)" do
      changeset =
        base_record(%{code_challenge_method: "plain"})
        |> Authorization.from_record(now: @now)

      refute changeset.valid?
      assert %{code_challenge_method: ["is invalid"]} = errors_on(changeset)
    end
  end

  describe "to_record/1" do
    test "rebuilds the grant :data shape expected by the protocol layer" do
      row = %Authorization{
        code_hash: "hash-of-the-code",
        client_id: "client-123",
        subject: "subject-abc",
        scope: ["read", "write"],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: "S256",
        cnf: nil,
        nonce: "n-0S6_WzA2Mj",
        claims: %{"acr" => "phr"},
        family_id: "fam-record",
        expires_at: ~U[2024-01-01 00:01:00Z]
      }

      record = Authorization.to_record(row)

      assert record.code_hash == "hash-of-the-code"
      assert record.expires_at == @expires_unix

      assert record.data == %{
               client_id: "client-123",
               subject: "subject-abc",
               scope: ["read", "write"],
               redirect_uri: "https://rp.example/cb",
               code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
               code_challenge_method: "S256",
               dpop_jkt: nil,
               nonce: "n-0S6_WzA2Mj",
               claims: %{"acr" => "phr"},
               family_id: "fam-record"
             }
    end

    test "flattens a cnf binding back to dpop_jkt" do
      row = %Authorization{
        code_hash: "h",
        client_id: "c",
        subject: "s",
        scope: [],
        redirect_uri: "https://rp.example/cb",
        code_challenge: "chal",
        code_challenge_method: "S256",
        cnf: %{"jkt" => "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"},
        claims: %{},
        expires_at: ~U[2024-01-01 00:01:00Z]
      }

      record = Authorization.to_record(row)

      assert record.data.dpop_jkt == "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    end

    test "defaults nil scope and claims to empty containers" do
      row = %Authorization{
        code_hash: "h",
        client_id: "c",
        subject: "s",
        scope: nil,
        redirect_uri: "https://rp.example/cb",
        code_challenge: "chal",
        code_challenge_method: "S256",
        cnf: nil,
        claims: nil,
        expires_at: ~U[2024-01-01 00:01:00Z]
      }

      record = Authorization.to_record(row)

      assert record.data.scope == []
      assert record.data.claims == %{}
    end
  end

  describe "from_record/2 then to_record/1 round-trip" do
    test "preserves the grant context for a DPoP-bound code" do
      original =
        base_record(%{dpop_jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", nonce: "nn"})

      row =
        original
        |> Authorization.from_record(now: @now)
        |> Ecto.Changeset.apply_changes()

      record = Authorization.to_record(row)

      assert record.code_hash == original.code_hash
      assert record.expires_at == original.expires_at
      assert record.data.client_id == original.data.client_id
      assert record.data.subject == original.data.subject
      assert record.data.scope == original.data.scope
      assert record.data.redirect_uri == original.data.redirect_uri
      assert record.data.code_challenge == original.data.code_challenge
      assert record.data.dpop_jkt == original.data.dpop_jkt
      assert record.data.family_id == Map.get(original.data, :family_id)
      assert record.data.nonce == original.data.nonce
      assert record.data.claims == original.data.claims
    end
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
