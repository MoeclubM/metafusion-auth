package store

import (
	"context"
	"strings"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
	"github.com/google/uuid"
)

func TestUsernameCaseInsensitiveAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	db := testutil.Database(t)
	s := &Store{DB: db}
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	testutil.ResetAccounts(t, db)
	t.Cleanup(func() { testutil.ResetAccounts(t, db) })
	const password = "Case-Sensitive-Password"
	admin, err := s.CreateUser(ctx, "CaseAdmin", "admin@example.test", password, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, login := range []string{"CaseAdmin", "caseadmin", "CASEADMIN", "  CaSeAdMiN  "} {
		_, user, err := s.Login(ctx, login, password)
		if err != nil || user.ID != admin.ID || user.Username != "CaseAdmin" {
			t.Fatalf("login %q: user=%+v err=%v", login, user, err)
		}
	}
	if _, _, err := s.Login(ctx, "caseadmin", strings.ToLower(password)); err == nil {
		t.Fatal("password must remain case-sensitive")
	}
	if _, err := s.CreateUser(ctx, "CASEADMIN", "other@example.test", password, false, &admin); err == nil {
		t.Fatal("admin creation allowed case duplicate")
	}
	restoreSettings(t, db, SettingRegistrationEnabled, SettingInviteRequired)
	if err := s.UpdateSettings(ctx, map[string]any{SettingRegistrationEnabled: true, SettingInviteRequired: false}, &admin); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(ctx, "caseADMIN", "new@example.test", password, ""); err == nil || err.Error() != "username_or_email_taken" {
		t.Fatalf("register duplicate: %v", err)
	}
	// Database uniqueness must protect direct writes and older application instances too.
	if _, err := db.ExecContext(ctx, "INSERT INTO auth.users(id,username,email,password_hash) VALUES($1,$2,$3,$4)", uuid.NewString(), "CASEadmin", "direct@example.test", "unused"); err == nil {
		t.Fatal("index allowed case duplicate")
	}
	// Do not resolve a cross-namespace ambiguity by whichever row PostgreSQL returns first.
	if _, err := s.CreateUser(ctx, "OtherUser", "caseadmin", password, false, &admin); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Login(ctx, "caseadmin", password); err == nil {
		t.Fatal("ambiguous username/email login was accepted")
	}
}

func TestUsernameCaseMigrationRejectsLegacyCollisions(t *testing.T) {
	ctx := context.Background()
	db := testutil.Database(t)
	s := &Store{DB: db}
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	testutil.ResetAccounts(t, db)
	t.Cleanup(func() {
		testutil.ResetAccounts(t, db)
		if err := s.Init(ctx); err != nil {
			t.Errorf("restore index: %v", err)
		}
	})
	if _, err := db.ExecContext(ctx, "DROP INDEX auth.users_username_lower_key"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"LegacyName", "legacyname"} {
		if _, err := db.ExecContext(ctx, "INSERT INTO auth.users(id,username,password_hash) VALUES($1,$2,$3)", uuid.NewString(), name, "unused"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Init(ctx); err == nil || !strings.Contains(err.Error(), "username_case_conflict") {
		t.Fatalf("expected actionable collision error: %v", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM auth.users").Scan(&count); err != nil || count != 2 {
		t.Fatalf("migration altered existing accounts: count=%d err=%v", count, err)
	}
	// Fail closed even if an operator starts this binary against the pre-migration schema.
	if _, _, err := s.Login(ctx, "LEGACYNAME", "unused"); err == nil {
		t.Fatal("legacy ambiguity accepted")
	}
	testutil.ResetAccounts(t, db)
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(ctx); err != nil {
		t.Fatalf("migration must be idempotent: %v", err)
	}
}
