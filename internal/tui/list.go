package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/puzakov/gophkeeper-exam/internal/client"
	"github.com/puzakov/gophkeeper-exam/internal/model"
)

// ListModel displays the user's secrets with type filtering.
type ListModel struct {
	goph     *client.GophKeeperClient
	secrets  []model.SecretSummary
	filtered []model.SecretSummary
	filter   string // "", "login_password", "text", "binary", "bank_card"
	cursor   int
	loading  bool
	spinner  spinner.Model
	err      string
	width    int
}

// NewListModel creates the secret list screen.
func NewListModel(goph *client.GophKeeperClient) *ListModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(accent)

	return &ListModel{
		goph:    goph,
		filter:  "",
		spinner: s,
	}
}

func (m *ListModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.loadSecrets())
}

func (m *ListModel) loadSecrets() tea.Cmd {
	return func() tea.Msg {
		secrets, err := m.goph.ListSecrets(context.Background())
		if err != nil {
			return listErrMsg{err: err.Error()}
		}
		return listLoadedMsg{secrets: secrets}
	}
}

type listLoadedMsg struct{ secrets []model.SecretSummary }
type listErrMsg struct{ err string }

func (m *ListModel) Update(msg tea.Msg) (*ListModel, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case listLoadedMsg:
		m.loading = false
		m.secrets = msg.secrets
		m.applyFilter()
		return m, nil

	case listErrMsg:
		m.loading = false
		m.err = msg.err
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.filtered)-1 {
				m.cursor++
			}

		case "enter":
			if len(m.filtered) > 0 && m.cursor < len(m.filtered) {
				id := m.filtered[m.cursor].ID.String()
				return m, NavigateToDetail(id)
			}

		case "n":
			if m.goph != nil && !m.goph.IsOnline() {
				m.err = "offline — read-only mode, cannot create secrets"
				return m, nil
			}
			return m, NavigateToForm(nil)

		case "1":
			m.filter = ""
			m.applyFilter()
		case "2":
			m.filter = "login_password"
			m.applyFilter()
		case "3":
			m.filter = "text"
			m.applyFilter()
		case "4":
			m.filter = "binary"
			m.applyFilter()
		case "5":
			m.filter = "bank_card"
			m.applyFilter()

		case "r":
			m.loading = true
			m.err = ""
			return m, tea.Batch(m.spinner.Tick, m.loadSecrets())

		case "s":
			return m, func() tea.Msg {
				_, err := m.goph.Sync(context.Background(), nil, nil)
				if err != nil {
					return listErrMsg{err: "sync: " + err.Error()}
				}
				return nil
			}
		}
	}
	return m, nil
}

func (m *ListModel) applyFilter() {
	m.filtered = nil
	m.cursor = 0
	for _, s := range m.secrets {
		if m.filter == "" || s.Type.String() == m.filter {
			m.filtered = append(m.filtered, s)
		}
	}
}

func (m *ListModel) View() string {
	var b strings.Builder

	// Header with connectivity badge.
	header := SubtitleStyle.Render("Secrets")
	badge := m.statusBadge()
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, header, "  ", badge))
	b.WriteString("\n")

	// Filter tabs.
	tabs := []struct {
		key   string
		label string
	}{
		{"", "ALL (1)"},
		{"login_password", "LOGINS (2)"},
		{"text", "TEXT (3)"},
		{"binary", "BINARY (4)"},
		{"bank_card", "CARDS (5)"},
	}
	var tabViews []string
	for _, t := range tabs {
		if m.filter == t.key {
			tabViews = append(tabViews, ActiveTabStyle.Render(t.label))
		} else {
			tabViews = append(tabViews, InactiveTabStyle.Render(t.label))
		}
	}
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, tabViews...))
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString(m.spinner.View() + " Loading...")
		b.WriteString("\n")
		return b.String()
	}

	if m.err != "" {
		b.WriteString(ErrorStyle.Render("✗ " + m.err))
		b.WriteString("\n")
	}

	if len(m.filtered) == 0 {
		b.WriteString(DimStyle.Render("No secrets yet. Press 'n' to create one."))
		b.WriteString("\n")
	} else {
		b.WriteString(DimStyle.Render(fmt.Sprintf("%d secrets", len(m.filtered))))
		b.WriteString("\n\n")

		for i, s := range m.filtered {
			prefix := "  "
			style := ItemStyle
			if i == m.cursor {
				prefix = "▶ "
				style = SelectedStyle
			}

			c := TypeColour(s.Type.String())
			typ := lipgloss.NewStyle().Foreground(c).Render(fmt.Sprintf("[%s]", s.Type.String()))
			comment := s.Comment
			if comment == "" {
				comment = DimStyle.Render("(no label)")
			}

			line := fmt.Sprintf("%s%s %s  %s", prefix, typ, comment, DimStyle.Render(s.ID.String()[:8]+"..."))
			b.WriteString(style.Render(line))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(DimStyle.Render("↑↓: navigate  •  enter: open  •  n: new  •  r: refresh  •  s: sync  •  q: quit"))

	return b.String()
}

// statusBadge renders the connectivity indicator.
func (m *ListModel) statusBadge() string {
	if m.goph == nil {
		return ""
	}
	if m.goph.IsOnline() {
		return lipgloss.NewStyle().Foreground(success).Render("● ONLINE")
	}
	return lipgloss.NewStyle().Foreground(warning).Render("○ OFFLINE (read-only)")
}
