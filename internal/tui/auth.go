package tui

import (
	"context"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/puzakov/gophkeeper-exam/internal/client"
)

// AuthModel is the login/register/unlock screen.
type AuthModel struct {
	goph    *client.GophKeeperClient
	mode    string // "login", "register", or "unlock"
	login   textinput.Model
	pass    textinput.Model
	confirm textinput.Model // only used in register mode
	err     string
	focus   int // 0=login, 1=password, 2=confirm
}

// NewAuthModel creates the auth screen.
func NewAuthModel(goph *client.GophKeeperClient) *AuthModel {
	li := textinput.New()
	li.Placeholder = "login"
	li.CharLimit = 255

	pi := textinput.New()
	pi.Placeholder = "master password"
	pi.EchoMode = textinput.EchoPassword
	pi.CharLimit = 128

	ci := textinput.New()
	ci.Placeholder = "confirm password"
	ci.EchoMode = textinput.EchoPassword
	ci.CharLimit = 128

	mode := "login"
	focusIdx := 0

	if goph.IsLoggedIn() && !goph.HasKeyMaterial() {
		savedLogin := goph.SavedLogin()
		if savedLogin != "" {
			mode = "unlock"
			li.SetValue(savedLogin)
			pi.Focus()
			focusIdx = 1
		}
	} else {
		li.Focus()
	}

	return &AuthModel{
		goph:    goph,
		mode:    mode,
		login:   li,
		pass:    pi,
		confirm: ci,
		focus:   focusIdx,
	}
}

func (m *AuthModel) numFields() int {
	if m.mode == "register" {
		return 3
	}
	if m.mode == "unlock" {
		return 1 // only password
	}
	return 2
}

func (m *AuthModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m *AuthModel) Update(msg tea.Msg) (*AuthModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "shift+tab", "down", "up":
			n := m.numFields()
			if n <= 1 {
				return m, nil
			}
			m.focus = (m.focus + 1) % n
			// Skip login field in unlock mode (it's at index 0).
			if m.mode == "unlock" && m.focus == 0 {
				m.focus = 1
			}
			m.updateFocus()
			return m, nil

		case "enter":
			return m, m.submit()

		case "ctrl+l":
			m.switchTo("login")
			return m, nil

		case "ctrl+r":
			m.switchTo("register")
			return m, nil

		case "ctrl+d":
			_ = m.goph.ClearTokens()
			m.switchTo("login")
			return m, nil
		}
	}

	return m, m.updateField(msg)
}

func (m *AuthModel) updateField(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch m.focus {
	case 0:
		m.login, cmd = m.login.Update(msg)
	case 1:
		m.pass, cmd = m.pass.Update(msg)
	case 2:
		m.confirm, cmd = m.confirm.Update(msg)
	}
	return cmd
}

func (m *AuthModel) updateFocus() {
	m.login.Blur()
	m.pass.Blur()
	m.confirm.Blur()

	switch m.focus {
	case 0:
		m.login.Focus()
	case 1:
		m.pass.Focus()
	case 2:
		m.confirm.Focus()
	}
}

func (m *AuthModel) switchTo(mode string) {
	m.mode = mode
	m.err = ""
	m.focus = 0
	m.login.Reset()
	m.login.SetValue("")
	m.login.Placeholder = "login"
	m.login.Focus()
	m.pass.Reset()
	m.pass.SetValue("")
	m.pass.Blur()
	m.confirm.Reset()
	m.confirm.SetValue("")
	m.confirm.Blur()
}

func (m *AuthModel) submit() tea.Cmd {
	login := strings.TrimSpace(m.login.Value())
	password := m.pass.Value()

	if login == "" || password == "" {
		m.err = "login and password are required"
		return nil
	}

	if m.mode == "register" {
		confirm := m.confirm.Value()
		if password != confirm {
			m.err = "passwords do not match"
			return nil
		}
	}

	return func() tea.Msg {
		ctx := context.Background()
		var err error

		switch m.mode {
		case "register":
			err = m.goph.Register(ctx, login, password)
		case "login", "unlock":
			err = m.goph.Login(ctx, login, password)
		}

		if err != nil {
			return authErrMsg{err: err.Error()}
		}
		return authOKMsg{}
	}
}

func (m *AuthModel) View() string {
	var b strings.Builder

	switch m.mode {
	case "unlock":
		b.WriteString(SubtitleStyle.Render("🔓 Unlock Vault"))
		b.WriteString("\n\n")
		b.WriteString(DimStyle.Render("Session found. Enter your master password."))
		b.WriteString("\n\n")
	case "register":
		b.WriteString(SubtitleStyle.Render("Create Account"))
		b.WriteString("\n\n")
	default:
		b.WriteString(SubtitleStyle.Render("Sign In"))
		b.WriteString("\n\n")
	}

	// Login field (hidden in unlock mode).
	if m.mode != "unlock" {
		b.WriteString(LabelStyle.Render("Login:"))
		b.WriteString("\n")
		b.WriteString(m.login.View())
		b.WriteString("\n\n")
	}

	// Password field.
	b.WriteString(LabelStyle.Render("Master Password:"))
	b.WriteString("\n")
	b.WriteString(m.pass.View())
	b.WriteString("\n\n")

	// Confirm password (register only).
	if m.mode == "register" {
		b.WriteString(LabelStyle.Render("Confirm Password:"))
		b.WriteString("\n")
		b.WriteString(m.confirm.View())
		b.WriteString("\n\n")
	}

	if m.err != "" {
		b.WriteString(ErrorStyle.Render("✗ " + m.err))
		b.WriteString("\n\n")
	}

	switch m.mode {
	case "unlock":
		b.WriteString(DimStyle.Render("enter: unlock  •  ctrl+l: new login  •  ctrl+r: register  •  ctrl+d: clear  •  ctrl+c: quit"))
	case "register":
		b.WriteString(DimStyle.Render("ctrl+l: login  •  enter: submit  •  ctrl+d: clear  •  ctrl+c: quit"))
	default:
		b.WriteString(DimStyle.Render("ctrl+l: login  •  ctrl+r: register  •  ctrl+d: clear  •  enter: submit  •  ctrl+c: quit"))
	}

	return b.String()
}

// Messages.
type authErrMsg struct{ err string }
type authOKMsg struct{}
