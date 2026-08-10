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
	goph  *client.GophKeeperClient
	mode  string // "login", "register", or "unlock"
	login textinput.Model
	pass  textinput.Model
	err   string
	focus int // 0=login, 1=password
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

	mode := "login"
	focusIdx := 0

	// If tokens exist but no DEK — try "unlock" mode.
	if goph.IsLoggedIn() && !goph.HasKeyMaterial() {
		savedLogin := goph.SavedLogin()
		if savedLogin != "" {
			mode = "unlock"
			li.SetValue(savedLogin)
			pi.Focus()
			focusIdx = 1
		}
		// If savedLogin is empty, fall through to normal login mode.
	} else {
		li.Focus()
	}

	return &AuthModel{
		goph:  goph,
		mode:  mode,
		login: li,
		pass:  pi,
		focus: focusIdx,
	}
}

func (m *AuthModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m *AuthModel) Update(msg tea.Msg) (*AuthModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "shift+tab", "down", "up":
			if m.mode == "unlock" {
				return m, nil // only password is editable
			}
			m.focus = (m.focus + 1) % 2
			if m.focus == 0 {
				m.login.Focus()
				m.pass.Blur()
			} else {
				m.login.Blur()
				m.pass.Focus()
			}
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
			// Drop saved session.
			_ = m.goph.ClearTokens()
			m.switchTo("login")
			return m, nil
		}
	}

	var cmd tea.Cmd
	if m.mode == "unlock" || m.focus == 1 {
		m.pass, cmd = m.pass.Update(msg)
	} else {
		m.login, cmd = m.login.Update(msg)
	}
	return m, cmd
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
}

func (m *AuthModel) submit() tea.Cmd {
	login := strings.TrimSpace(m.login.Value())
	password := m.pass.Value()

	if login == "" || password == "" {
		m.err = "login and password are required"
		return nil
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

	if m.mode == "unlock" {
		b.WriteString(LabelStyle.Render("Account:"))
		b.WriteString("\n  ")
		b.WriteString(m.login.Value())
		b.WriteString("\n\n")
	} else {
		b.WriteString(LabelStyle.Render("Login:"))
		b.WriteString("\n")
		b.WriteString(m.login.View())
		b.WriteString("\n\n")
	}

	b.WriteString(LabelStyle.Render("Master Password:"))
	b.WriteString("\n")
	b.WriteString(m.pass.View())
	b.WriteString("\n\n")

	if m.err != "" {
		b.WriteString(ErrorStyle.Render("✗ " + m.err))
		b.WriteString("\n\n")
	}

	switch m.mode {
	case "unlock":
		b.WriteString(DimStyle.Render("enter: unlock  •  ctrl+l: new login  •  ctrl+r: register  •  ctrl+d: clear session  •  ctrl+c: quit"))
	default:
		b.WriteString(DimStyle.Render("ctrl+l: login  •  ctrl+r: register  •  ctrl+d: clear session  •  enter: submit  •  ctrl+c: quit"))
	}

	return b.String()
}

// Messages.
type authErrMsg struct{ err string }
type authOKMsg struct{}
