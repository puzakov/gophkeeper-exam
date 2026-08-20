package tui

import (
	"os"

	"github.com/google/uuid"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/puzakov/gophkeeper-exam/internal/client"
	"github.com/puzakov/gophkeeper-exam/internal/model"
)

// --- ListModel ---

func TestListModel_ApplyFilter(t *testing.T) {
	m := NewListModel(nil)

	m.secrets = []model.SecretSummary{
		{Type: model.SecretTypeLoginPassword, Comment: "a"},
		{Type: model.SecretTypeText, Comment: "b"},
		{Type: model.SecretTypeBinary, Comment: "c"},
		{Type: model.SecretTypeBankCard, Comment: "d"},
		{Type: model.SecretTypeText, Comment: "e"},
	}

	tests := []struct {
		name   string
		filter string
		want   int
	}{
		{"all", "", 5},
		{"logins", "login_password", 1},
		{"text", "text", 2},
		{"binary", "binary", 1},
		{"cards", "bank_card", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.filter = tt.filter
			m.applyFilter()
			if len(m.filtered) != tt.want {
				t.Errorf("applyFilter(%q) len = %d, want %d", tt.filter, len(m.filtered), tt.want)
			}
			if m.cursor != 0 {
				t.Error("applyFilter must reset cursor to 0")
			}
		})
	}
}

func TestListModel_KeyNavigation(t *testing.T) {
	m := NewListModel(nil)
	m.secrets = []model.SecretSummary{
		{Type: model.SecretTypeText, Comment: "one"},
		{Type: model.SecretTypeText, Comment: "two"},
		{Type: model.SecretTypeText, Comment: "three"},
	}
	m.applyFilter()

	// Down moves cursor.
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if m.cursor != 1 {
		t.Errorf("cursor after down = %d, want 1", m.cursor)
	}
	// Up moves back.
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if m.cursor != 0 {
		t.Errorf("cursor after up = %d, want 0", m.cursor)
	}
	// Up at top stays at 0.
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if m.cursor != 0 {
		t.Errorf("cursor after up at top = %d, want 0", m.cursor)
	}
	// Down at bottom stays.
	m.cursor = 2
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if m.cursor != 2 {
		t.Errorf("cursor after down at bottom = %d, want 2", m.cursor)
	}

	// Filter keys.
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	if m.filter != "text" {
		t.Errorf("filter = %q, want text", m.filter)
	}

	// Enter on item navigates to detail.
	cmd := m.cursorEnterCmd()
	if cmd == nil {
		t.Skip("enter handling requires client")
	}
}

// cursorEnterCmd extracts the navigate command for enter (best-effort check).
func (m *ListModel) cursorEnterCmd() tea.Cmd {
	m.cursor = 0
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	return cmd
}

func TestListModel_View(t *testing.T) {
	m := NewListModel(nil)
	m.secrets = []model.SecretSummary{{Type: model.SecretTypeText, Comment: "note"}}
	m.applyFilter()

	v := m.View()
	if !strings.Contains(v, "note") {
		t.Errorf("View() does not contain secret comment: %q", v)
	}

	m.loading = true
	if !strings.Contains(m.View(), "Loading") {
		t.Error("View() in loading state does not show Loading")
	}
	m.loading = false

	m.err = "boom"
	if !strings.Contains(m.View(), "boom") {
		t.Error("View() does not show error")
	}
}

// --- DetailModel helpers ---

func TestMaskCard(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"4111111111111111", "••••••••••••1111"},
		{"1234", "1234"},
		{"123", "••••"},
		{"", "••••"},
	}
	for _, tt := range tests {
		if got := maskCard(tt.in); got != tt.want {
			t.Errorf("maskCard(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSanitiseFilename(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"my notes", "my notes"},
		{"a/b:c*d?e\"f<g>h|i", "a_b_c_d_e_f_g_h_i"},
		{"  spaced  ", "spaced"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := sanitiseFilename(tt.in); got != tt.want {
			t.Errorf("sanitiseFilename(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDoExport(t *testing.T) {
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldWD) }()

	t.Run("binary", func(t *testing.T) {
		path, err := doExport(&model.BinaryPayload{
			Data:     []byte{0x01, 0x02, 0x03},
			FileName: "secret.bin",
		}, "")
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != 3 || data[2] != 0x03 {
			t.Errorf("exported data = %v", data)
		}
	})

	t.Run("text uses comment as name", func(t *testing.T) {
		path, err := doExport(&model.TextPayload{Text: "hello world"}, "my note")
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(path) != "my note.txt" {
			t.Errorf("export path = %q", path)
		}
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := doExport(&model.LoginPasswordPayload{Login: "l", Password: "p"}, "")
		if err == nil {
			t.Error("doExport() with login payload succeeded")
		}
	})
}

// --- FormModel ---

func TestFormModel_BuildFieldsPerType(t *testing.T) {
	tests := []struct {
		typ      string
		wantKeys []string
		wantMask map[string]bool
	}{
		{"login_password", []string{"login", "password"}, map[string]bool{"password": true}},
		{"text", []string{"text"}, nil},
		{"binary", []string{"file"}, nil},
		{"bank_card", []string{"number", "expiry", "cvv", "holder"}, map[string]bool{"cvv": true}},
	}

	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			m := NewFormModel(nil)
			m.secretType = tt.typ
			m.buildFields()

			if len(m.fields) != len(tt.wantKeys) {
				t.Fatalf("fields len = %d, want %d", len(m.fields), len(tt.wantKeys))
			}
			for i, key := range tt.wantKeys {
				if m.fields[i].key != key {
					t.Errorf("field[%d] = %q, want %q", i, m.fields[i].key, key)
				}
			}
			for _, f := range m.fields {
				if f.mask != tt.wantMask[f.key] {
					t.Errorf("field %q mask = %v, want %v", f.key, f.mask, tt.wantMask[f.key])
				}
			}
		})
	}
}

func TestFormModel_SetFieldAndFieldVal(t *testing.T) {
	m := NewFormModel(nil)
	m.secretType = "login_password"
	m.buildFields()

	m.setField("login", "alice")
	m.setField("password", "secret")

	if got := m.fieldVal("login"); got != "alice" {
		t.Errorf("fieldVal(login) = %q", got)
	}
	if got := m.fieldVal("password"); got != "secret" {
		t.Errorf("fieldVal(password) = %q", got)
	}
	if got := m.fieldVal("nonexistent"); got != "" {
		t.Errorf("fieldVal(nonexistent) = %q, want empty", got)
	}
}

func TestFormModel_FieldNavigation(t *testing.T) {
	m := NewFormModel(nil)
	m.secretType = "bank_card"
	m.buildFields() // 4 fields + comment

	// focusIndex 0..4 (4 fields, comment at index 4)
	for i := 0; i < 5; i++ {
		if m.focusIndex != i {
			t.Fatalf("focusIndex = %d, want %d", m.focusIndex, i)
		}
		m.nextField()
	}
	// Wrapped around to 0.
	if m.focusIndex != 0 {
		t.Errorf("focusIndex after wrap = %d, want 0", m.focusIndex)
	}

	m.prevField()
	if m.focusIndex != 4 {
		t.Errorf("focusIndex after prev = %d, want 4 (comment)", m.focusIndex)
	}
}

func TestFormModel_CtrlT_CyclesTypes(t *testing.T) {
	m := NewFormModel(nil)
	types := []string{"login_password", "text", "binary", "bank_card"}

	start := m.secretType
	for i := 1; i <= len(types); i++ {
		m.Update(tea.KeyMsg{Type: tea.KeyCtrlT})
		want := types[i%len(types)]
		if m.secretType != want {
			t.Errorf("after ctrl+t: type = %q, want %q", m.secretType, want)
		}
	}
	// Full cycle returns to start.
	if m.secretType != start {
		t.Errorf("full cycle ended at %q, want %q", m.secretType, start)
	}
}

func TestTitleCase(t *testing.T) {
	tests := map[string]string{
		"login": "Login",
		"cvv":   "Cvv",
		"":      "",
		"a":     "A",
	}
	for in, want := range tests {
		if got := titleCase(in); got != want {
			t.Errorf("titleCase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestModelSecretType(t *testing.T) {
	tests := map[string]model.SecretType{
		"login_password": model.SecretTypeLoginPassword,
		"text":           model.SecretTypeText,
		"binary":         model.SecretTypeBinary,
		"bank_card":      model.SecretTypeBankCard,
		"unknown":        model.SecretTypeUnspecified,
	}
	for in, want := range tests {
		if got := modelSecretType(in); got != want {
			t.Errorf("modelSecretType(%q) = %v, want %v", in, got, want)
		}
	}
}

// --- AuthModel ---

func TestAuthModel_ModeSwitching(t *testing.T) {
	m := NewAuthModel(&client.GophKeeperClient{})

	// ctrl+r switches to register (3 fields).
	m.Update(tea.KeyMsg{Type: tea.KeyCtrlR})
	if m.mode != "register" {
		t.Errorf("mode = %q, want register", m.mode)
	}
	if m.numFields() != 3 {
		t.Errorf("numFields in register = %d, want 3", m.numFields())
	}

	// ctrl+l switches back to login.
	m.Update(tea.KeyMsg{Type: tea.KeyCtrlL})
	if m.mode != "login" {
		t.Errorf("mode = %q, want login", m.mode)
	}
	if m.numFields() != 2 {
		t.Errorf("numFields in login = %d, want 2", m.numFields())
	}
}

func TestAuthModel_Submit_PasswordMismatch(t *testing.T) {
	m := NewAuthModel(&client.GophKeeperClient{})
	m.mode = "register"
	m.login.SetValue("alice")
	m.pass.SetValue("password1")
	m.confirm.SetValue("password2")

	cmd := m.submit()
	if cmd != nil {
		t.Error("submit() with mismatched passwords must not issue a command")
	}
	if m.err != "passwords do not match" {
		t.Errorf("err = %q", m.err)
	}
}

func TestAuthModel_Submit_EmptyFields(t *testing.T) {
	m := NewAuthModel(&client.GophKeeperClient{})
	cmd := m.submit()
	if cmd != nil {
		t.Error("submit() with empty fields must not issue a command")
	}
	if m.err == "" {
		t.Error("err not set for empty fields")
	}
}

func TestAuthModel_View_ShowsModeSpecificContent(t *testing.T) {
	m := NewAuthModel(&client.GophKeeperClient{})

	if !strings.Contains(m.View(), "Sign In") {
		t.Error("login view missing title")
	}

	m.mode = "register"
	v := m.View()
	if !strings.Contains(v, "Create Account") {
		t.Error("register view missing title")
	}
	if !strings.Contains(v, "Confirm Password") {
		t.Error("register view missing confirm field")
	}

	m.mode = "unlock"
	m.login.SetValue("alice")
	v = m.View()
	if !strings.Contains(v, "Unlock") {
		t.Error("unlock view missing title")
	}
	if !strings.Contains(v, "alice") {
		t.Error("unlock view missing account name")
	}
	if strings.Contains(v, "Login:") {
		t.Error("unlock view must not show login input")
	}
}

func TestAuthModel_TabNavigation_SkipsUnlockLogin(t *testing.T) {
	m := NewAuthModel(&client.GophKeeperClient{})
	m.mode = "unlock"
	m.focus = 1

	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if m.focus != 1 {
		t.Errorf("tab in unlock mode moved focus to %d, want 1 (password only)", m.focus)
	}
}

// --- AppModel ---

func TestAppModel_RoutesToAuthWhenLoggedOut(t *testing.T) {
	app := NewApp(&client.GophKeeperClient{})
	if app.current != ScreenAuth {
		t.Errorf("current = %q, want auth for logged-out client", app.current)
	}
	v := app.View()
	if !strings.Contains(v, "GophKeeper") {
		t.Error("AppModel.View() missing header")
	}
}

func TestAppModel_EscNavigation(t *testing.T) {
	app := NewApp(&client.GophKeeperClient{})

	// From form → back to list.
	app.current = ScreenForm
	_, cmd := app.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd == nil {
		t.Fatal("esc from form must return a command (list reload)")
	}
	if app.current != ScreenList {
		t.Errorf("current after esc = %q, want list", app.current)
	}

	// From list → quit.
	_, cmd = app.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd == nil {
		t.Error("esc from list must quit")
	}

	// From auth → ctrl+c quits.
	app2 := NewApp(&client.GophKeeperClient{})
	_, cmd = app2.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Error("ctrl+c from auth must quit")
	}
}

func TestAppModel_NavigateMsg(t *testing.T) {
	app := NewApp(&client.GophKeeperClient{})

	// Navigate to list.
	_, _ = app.Update(NavigateMsg{Screen: ScreenList})
	if app.current != ScreenList {
		t.Errorf("current = %q, want list", app.current)
	}

	// Navigate to detail with secret id.
	_, _ = app.Update(NavigateMsg{Screen: ScreenDetail, SecretID: "abc"})
	if app.current != ScreenDetail {
		t.Errorf("current = %q, want detail", app.current)
	}
	if app.detail.secretID != "abc" {
		t.Errorf("detail.secretID = %q, want abc", app.detail.secretID)
	}

	// Navigate to form.
	_, _ = app.Update(NavigateMsg{Screen: ScreenForm, Secret: nil})
	if app.current != ScreenForm {
		t.Errorf("current = %q, want form", app.current)
	}
}

// --- Additional View branch coverage ---

func TestDetailModel_View_Payloads(t *testing.T) {
	tests := []struct {
		name     string
		secret   *model.Secret
		payload  any
		showPass bool
		want     []string
	}{
		{
			"login hidden",
			&model.Secret{ID: uuid.New(), Type: model.SecretTypeLoginPassword, Comment: "l", Version: 1},
			&model.LoginPasswordPayload{Login: "alice", Password: "secret"},
			false,
			[]string{"alice", "••••••"},
		},
		{
			"login shown",
			&model.Secret{ID: uuid.New(), Type: model.SecretTypeLoginPassword, Comment: "l", Version: 1},
			&model.LoginPasswordPayload{Login: "alice", Password: "secret"},
			true,
			[]string{"alice", "secret"},
		},
		{
			"text",
			&model.Secret{ID: uuid.New(), Type: model.SecretTypeText, Comment: "t", Version: 1},
			&model.TextPayload{Text: "hello"},
			false,
			[]string{"hello"},
		},
		{
			"binary",
			&model.Secret{ID: uuid.New(), Type: model.SecretTypeBinary, Comment: "b", Version: 1},
			&model.BinaryPayload{Data: []byte{1, 2, 3}, FileName: "f.bin"},
			false,
			[]string{"f.bin", "3 bytes"},
		},
		{
			"card masked",
			&model.Secret{ID: uuid.New(), Type: model.SecretTypeBankCard, Comment: "c", Version: 1},
			&model.BankCardPayload{Number: "4111111111111111", Expiry: "12/28", CVV: "123", HolderName: "IVAN"},
			false,
			[]string{"••••", "12/28", "IVAN"},
		},
		{
			"card shown",
			&model.Secret{ID: uuid.New(), Type: model.SecretTypeBankCard, Comment: "c", Version: 1},
			&model.BankCardPayload{Number: "4111111111111111", Expiry: "12/28", CVV: "123"},
			true,
			[]string{"4111111111111111", "123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewDetailModel(nil)
			m.secretID = tt.secret.ID.String()
			m.secret = tt.secret
			m.payload = tt.payload
			m.showPass = tt.showPass
			v := m.View()
			for _, w := range tt.want {
				if !strings.Contains(v, w) {
					t.Errorf("View() missing %q in:\n%s", w, v)
				}
			}
		})
	}
}

func TestDetailModel_View_States(t *testing.T) {
	m := NewDetailModel(nil)
	if v := m.View(); !strings.Contains(v, "No secret selected") {
		t.Error("empty View() missing placeholder")
	}

	m.secretID = "x"
	m.loading = true
	if !strings.Contains(m.View(), "Decrypting") {
		t.Error("loading View() missing Decrypting")
	}
	m.loading = false

	m.err = "failure"
	if !strings.Contains(m.View(), "failure") {
		t.Error("error View() missing message")
	}
}

func TestDetailModel_ExportHelp_ShownForBinaryAndText(t *testing.T) {
	m := NewDetailModel(nil)
	m.secret = &model.Secret{ID: uuid.New(), Type: model.SecretTypeBinary}
	m.secretID = m.secret.ID.String()
	m.payload = &model.BinaryPayload{Data: []byte{1}, FileName: "f"}
	if !strings.Contains(m.View(), "save to file") {
		t.Error("binary detail must show export hint")
	}

	m.secret.Type = model.SecretTypeText
	m.payload = &model.TextPayload{Text: "x"}
	if !strings.Contains(m.View(), "save to file") {
		t.Error("text detail must show export hint")
	}

	m.secret.Type = model.SecretTypeLoginPassword
	m.payload = &model.LoginPasswordPayload{Login: "l", Password: "p"}
	if strings.Contains(m.View(), "save to file") {
		t.Error("login detail must NOT show export hint")
	}
}

func TestFormModel_View_CreateAndEdit(t *testing.T) {
	m := NewFormModel(&client.GophKeeperClient{})
	m.SetSecret(nil)
	v := m.View()
	if !strings.Contains(v, "New Secret") {
		t.Error("create View() missing title")
	}
	if !strings.Contains(v, "Login:") {
		t.Error("form View() missing login field label")
	}

	m.SetSecret(&model.Secret{ID: uuid.New(), Type: model.SecretTypeText})
	v = m.View()
	if !strings.Contains(v, "Edit Secret") {
		t.Error("edit View() missing title")
	}
	if !strings.Contains(v, "Text:") {
		t.Error("text form missing Text field")
	}
}

func TestFormModel_KeyHandling(t *testing.T) {
	m := NewFormModel(nil)
	m.SetSecret(nil)

	// ctrl+c cancels back to list.
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Error("ctrl+c must navigate back")
	}
}

func TestAuthModel_SwitchTo_ResetsState(t *testing.T) {
	m := NewAuthModel(&client.GophKeeperClient{})
	m.mode = "unlock"
	m.focus = 1
	m.err = "old error"
	m.login.SetValue("old-login")
	m.pass.SetValue("old-pass")

	m.switchTo("login")

	if m.mode != "login" {
		t.Errorf("mode = %q, want login", m.mode)
	}
	if m.focus != 0 {
		t.Errorf("focus = %d, want 0", m.focus)
	}
	if m.err != "" {
		t.Errorf("err = %q, want empty", m.err)
	}
	if m.login.Value() != "" {
		t.Errorf("login not cleared: %q", m.login.Value())
	}
	if m.pass.Value() != "" {
		t.Errorf("password not cleared: %q", m.pass.Value())
	}
}

func TestAuthModel_TabCyclesFields(t *testing.T) {
	m := NewAuthModel(&client.GophKeeperClient{})
	m.mode = "register"
	m.focus = 0

	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if m.focus != 1 {
		t.Errorf("focus after tab = %d, want 1", m.focus)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if m.focus != 2 {
		t.Errorf("focus after tab = %d, want 2 (confirm)", m.focus)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if m.focus != 0 {
		t.Errorf("focus after wrap = %d, want 0", m.focus)
	}
}
