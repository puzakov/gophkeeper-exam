package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"

	"github.com/puzakov/gophkeeper-exam/internal/client"
	"github.com/puzakov/gophkeeper-exam/internal/model"
)

// DetailModel shows a decrypted secret's contents.
type DetailModel struct {
	goph     *client.GophKeeperClient
	secretID string
	secret   *model.Secret
	payload  any
	meta     model.Metadata
	loading  bool
	spinner  spinner.Model
	err      string
	msg      string
	showPass bool
}

// NewDetailModel creates the detail screen.
func NewDetailModel(goph *client.GophKeeperClient) *DetailModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(accent)

	return &DetailModel{goph: goph, spinner: s}
}

// SetSecretID sets the secret to display and triggers loading.
func (m *DetailModel) SetSecretID(id string) {
	m.secretID = id
	m.loading = true
	m.err = ""
	m.msg = ""
	m.showPass = false
}

type detailLoadedMsg struct {
	secret  *model.Secret
	payload any
	meta    model.Metadata
	err     string
}

type exportOKMsg struct{ path string }
type exportErrMsg struct{ err string }

func (m *DetailModel) load() tea.Cmd {
	return func() tea.Msg {
		id, _ := uuid.Parse(m.secretID)
		sec, payload, meta, err := m.goph.GetSecret(context.Background(), id)
		if err != nil {
			return detailLoadedMsg{err: err.Error()}
		}
		return detailLoadedMsg{secret: sec, payload: payload, meta: meta}
	}
}

func (m *DetailModel) Update(msg tea.Msg) (*DetailModel, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case detailLoadedMsg:
		m.loading = false
		if msg.err != "" {
			m.err = msg.err
		} else {
			m.secret = msg.secret
			m.payload = msg.payload
			m.meta = msg.meta
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "p":
			m.showPass = !m.showPass
			m.msg = ""
		case "e":
			if m.secret != nil {
				return m, NavigateToForm(m.secret)
			}
		case "d":
			if m.secret != nil {
				return m, m.deleteSecret()
			}
		case "x":
			return m, m.exportToFile()
		case "backspace":
			return m, Navigate(ScreenList)
		}
	}
	return m, nil
}

func (m *DetailModel) deleteSecret() tea.Cmd {
	return func() tea.Msg {
		id, _ := uuid.Parse(m.secretID)
		if err := m.goph.DeleteSecret(context.Background(), id); err != nil {
			return detailLoadedMsg{err: err.Error()}
		}
		return NavigateMsg{Screen: ScreenList}
	}
}

func (m *DetailModel) exportToFile() tea.Cmd {
	return func() tea.Msg {
		path, err := doExport(m.payload, m.secret.Comment)
		if err != nil {
			return exportErrMsg{err: err.Error()}
		}
		return exportOKMsg{path: path}
	}
}

func doExport(payload any, comment string) (string, error) {
	var data []byte
	var name string

	switch p := payload.(type) {
	case *model.BinaryPayload:
		data = p.Data
		name = p.FileName
		if name == "" {
			name = "export.bin"
		}
	case *model.TextPayload:
		data = []byte(p.Text)
		name = sanitiseFilename(comment)
		if name == "" {
			name = "export.txt"
		}
		if !strings.HasSuffix(name, ".txt") {
			name += ".txt"
		}
	default:
		return "", fmt.Errorf("export not supported for this secret type; use for binary or text secrets")
	}

	// Write to current directory.
	if err := os.WriteFile(name, data, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", name, err)
	}

	abs, _ := filepath.Abs(name)
	return abs, nil
}

func sanitiseFilename(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Replace path separators and other unsafe chars.
	replacer := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_", "?", "_",
		"\"", "_", "<", "_", ">", "_", "|", "_",
	)
	return replacer.Replace(s)
}

func (m *DetailModel) View() string {
	var b strings.Builder

	if m.secretID == "" {
		return "No secret selected."
	}

	if m.loading {
		b.WriteString(m.spinner.View() + " Decrypting...")
		return b.String()
	}

	if m.err != "" {
		b.WriteString(ErrorStyle.Render("✗ " + m.err))
		b.WriteString("\n\nPress backspace to go back.")
		return b.String()
	}

	if m.secret == nil {
		return "No data."
	}

	// Header.
	typ := lipgloss.NewStyle().Foreground(TypeColour(m.secret.Type.String())).Render(m.secret.Type.String())
	b.WriteString(SubtitleStyle.Render(fmt.Sprintf("%s  %s", typ, m.secret.Comment)))
	b.WriteString("\n")
	b.WriteString(DimStyle.Render(fmt.Sprintf("ID: %s  •  v%d", m.secret.ID.String(), m.secret.Version)))
	b.WriteString("\n\n")

	// Payload.
	switch p := m.payload.(type) {
	case *model.LoginPasswordPayload:
		b.WriteString(LabelStyle.Render("Login:"))
		b.WriteString("\n  " + p.Login)
		b.WriteString("\n\n")
		b.WriteString(LabelStyle.Render("Password:"))
		b.WriteString("\n  ")
		if m.showPass {
			b.WriteString(p.Password)
		} else {
			b.WriteString(strings.Repeat("•", len(p.Password)))
		}
		b.WriteString("\n")

	case *model.TextPayload:
		b.WriteString(LabelStyle.Render("Text:"))
		b.WriteString("\n" + p.Text)
		b.WriteString("\n")

	case *model.BinaryPayload:
		b.WriteString(LabelStyle.Render("File:"))
		b.WriteString("\n  " + p.FileName)
		b.WriteString(DimStyle.Render(fmt.Sprintf("  (%d bytes)", len(p.Data))))
		b.WriteString("\n")

	case *model.BankCardPayload:
		b.WriteString(LabelStyle.Render("Card Number:"))
		b.WriteString("\n  ")
		if m.showPass {
			b.WriteString(p.Number)
		} else {
			b.WriteString(maskCard(p.Number))
		}
		b.WriteString("\n\n")
		b.WriteString(LabelStyle.Render("Expiry:") + "  " + p.Expiry)
		b.WriteString("\n\n")
		b.WriteString(LabelStyle.Render("CVV:"))
		b.WriteString("\n  ")
		if m.showPass {
			b.WriteString(p.CVV)
		} else {
			b.WriteString("•••")
		}
		if p.HolderName != "" {
			b.WriteString("\n\n" + LabelStyle.Render("Holder:") + "  " + p.HolderName)
		}
		b.WriteString("\n")
	}

	// Metadata.
	if len(m.meta) > 0 {
		b.WriteString("\n" + LabelStyle.Render("Metadata:"))
		b.WriteString("\n")
		data, _ := json.MarshalIndent(m.meta, "", "  ")
		b.WriteString(DimStyle.Render(string(data)))
		b.WriteString("\n")
	}

	// Success message (e.g. export path).
	if m.msg != "" {
		b.WriteString("\n" + SuccessStyle.Render("✓ exported to "+m.msg))
		b.WriteString("\n")
	}

	b.WriteString("\n")

	// Help — show export hint for binary/text.
	help := "p: show/hide  •  e: edit  •  d: delete  •  backspace: back"
	if _, ok := m.payload.(*model.BinaryPayload); ok {
		help += "  •  x: save to file"
	}
	if _, ok := m.payload.(*model.TextPayload); ok {
		help += "  •  x: save to file"
	}
	b.WriteString(DimStyle.Render(help))

	return b.String()
}

func maskCard(num string) string {
	if len(num) < 4 {
		return "••••"
	}
	return strings.Repeat("•", len(num)-4) + num[len(num)-4:]
}
