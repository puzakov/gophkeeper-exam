package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/puzakov/gophkeeper-exam/internal/client"
)

// Screen names.
const (
	ScreenAuth   = "auth"
	ScreenList   = "list"
	ScreenDetail = "detail"
	ScreenForm   = "form"
)

// AppModel is the root Bubbletea model that routes between screens.
type AppModel struct {
	goph    *client.GophKeeperClient
	current string
	width   int
	height  int

	auth   *AuthModel
	list   *ListModel
	detail *DetailModel
	form   *FormModel
}

// NewApp creates the root TUI application model.
func NewApp(goph *client.GophKeeperClient) *AppModel {
	m := &AppModel{
		goph:    goph,
		current: ScreenAuth,
	}

	// Only skip to list if we have both tokens AND DEK.
	if goph.IsLoggedIn() && goph.HasKeyMaterial() {
		m.current = ScreenList
		// Start the background connectivity monitor for the online session.
		goph.StartConnectivityMonitor(context.Background())
	}

	m.auth = NewAuthModel(goph)
	m.list = NewListModel(goph)
	m.detail = NewDetailModel(goph)
	m.form = NewFormModel(goph)

	return m
}

// Init is the first command run when the program starts.
func (m *AppModel) Init() tea.Cmd {
	if m.goph.IsLoggedIn() && m.goph.HasKeyMaterial() {
		return m.list.Init()
	}
	return m.auth.Init()
}

// Update processes messages and delegates to the active screen.
func (m *AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case NavigateMsg:
		m.current = msg.Screen
		switch msg.Screen {
		case ScreenList:
			return m, m.list.Init()
		case ScreenDetail:
			m.detail.SetSecretID(msg.SecretID)
			return m, m.detail.load()
		case ScreenForm:
			m.form.SetSecret(msg.Secret)
			return m, m.form.Init()
		case ScreenAuth:
			return m, m.auth.Init()
		}
		return m, nil

	// Auth sub-model messages.
	case authOKMsg:
		// Session established (online or offline unlock) — start monitoring.
		m.goph.StartConnectivityMonitor(context.Background())
		return m, Navigate(ScreenList)
	case authErrMsg:
		m.auth.err = msg.err
		return m, nil

	// Form sub-model messages.
	case formOKMsg:
		return m, Navigate(ScreenList)
	case formErrMsg:
		m.form.err = msg.err
		return m, nil

	// Export messages (from detail screen).
	case exportOKMsg:
		m.detail.msg = msg.path
		return m, nil
	case exportErrMsg:
		m.detail.err = msg.err
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			if m.current == ScreenAuth {
				return m, tea.Quit
			}
			// Same behaviour as esc for non-auth screens.
			switch m.current {
			case ScreenDetail, ScreenForm:
				m.current = ScreenList
				return m, m.list.Init()
			case ScreenList:
				return m, tea.Quit
			}
		case "esc":
			switch m.current {
			case ScreenDetail, ScreenForm:
				m.current = ScreenList
				return m, m.list.Init()
			case ScreenList:
				return m, tea.Quit
			}
		}
	}

	// Delegate to active screen.
	var cmd tea.Cmd
	switch m.current {
	case ScreenAuth:
		m.auth, cmd = m.auth.Update(msg)
	case ScreenList:
		m.list, cmd = m.list.Update(msg)
	case ScreenDetail:
		m.detail, cmd = m.detail.Update(msg)
	case ScreenForm:
		m.form, cmd = m.form.Update(msg)
	}

	return m, cmd
}

// View renders the current screen with a header and footer.
func (m *AppModel) View() string {
	header := TitleStyle.Render("🔐 GophKeeper")
	footer := HelpStyle.Render("esc: back  •  ctrl+c: quit")

	var content string
	switch m.current {
	case ScreenAuth:
		content = m.auth.View()
	case ScreenList:
		content = m.list.View()
	case ScreenDetail:
		content = m.detail.View()
	case ScreenForm:
		content = m.form.View()
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		content,
		footer,
	)
}

// NavigateMsg is sent to switch screens.
type NavigateMsg struct {
	Screen   string
	SecretID string
	Secret   any
}

// Navigate creates a command that switches to the given screen.
func Navigate(screen string) tea.Cmd {
	return func() tea.Msg { return NavigateMsg{Screen: screen} }
}

// NavigateToDetail creates a command that opens a secret detail view.
func NavigateToDetail(secretID string) tea.Cmd {
	return func() tea.Msg { return NavigateMsg{Screen: ScreenDetail, SecretID: secretID} }
}

// NavigateToForm creates a command that opens the form for a secret.
func NavigateToForm(secret any) tea.Cmd {
	return func() tea.Msg { return NavigateMsg{Screen: ScreenForm, Secret: secret} }
}
