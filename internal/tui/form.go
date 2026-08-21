package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/puzakov/gophkeeper-exam/internal/client"
	"github.com/puzakov/gophkeeper-exam/internal/model"
)

// FormModel is the create/edit secret screen.
type FormModel struct {
	goph       *client.GophKeeperClient
	editSecret *model.Secret // nil = create mode

	secretType string
	comment    textinput.Model
	fields     []formField
	focusIndex int
	err        string
}

type formField struct {
	key  string
	ti   textinput.Model
	mask bool
}

// NewFormModel creates the form screen.
func NewFormModel(goph *client.GophKeeperClient) *FormModel {
	m := &FormModel{
		goph:       goph,
		secretType: "login_password",
		comment:    textinput.New(),
	}
	m.comment.Placeholder = "label / comment"
	return m
}

// SetSecret configures the form for editing (non-nil) or creating (nil).
func (m *FormModel) SetSecret(sec any) {
	if sec == nil {
		m.editSecret = nil
		m.secretType = "login_password"
	} else if s, ok := sec.(*model.Secret); ok {
		m.editSecret = s
		m.secretType = s.Type.String()
	}
	m.focusIndex = 0
	m.err = ""
	m.buildFields()
}

func (m *FormModel) buildFields() {
	var keys []string
	var masks map[string]bool

	switch m.secretType {
	case "login_password":
		keys = []string{"login", "password"}
		masks = map[string]bool{"password": true}
	case "text":
		keys = []string{"text"}
	case "binary":
		keys = []string{"file"}
	case "bank_card":
		keys = []string{"number", "expiry", "cvv", "holder"}
		masks = map[string]bool{"cvv": true}
	default:
		return
	}

	m.fields = make([]formField, len(keys))
	for i, key := range keys {
		ti := textinput.New()
		ti.Placeholder = key
		ti.CharLimit = 2048
		if masks[key] {
			ti.EchoMode = textinput.EchoPassword
		}
		m.fields[i] = formField{key: key, ti: ti, mask: masks[key]}
	}

	// Pre-fill if editing.
	if m.editSecret != nil && m.goph.IsLoggedIn() {
		_, payload, _, err := m.goph.GetSecret(context.Background(), m.editSecret.ID)
		if err == nil {
			m.comment.SetValue(m.editSecret.Comment)
			switch p := payload.(type) {
			case *model.LoginPasswordPayload:
				m.setField("login", p.Login)
				m.setField("password", p.Password)
			case *model.TextPayload:
				m.setField("text", p.Text)
			case *model.BankCardPayload:
				m.setField("number", p.Number)
				m.setField("expiry", p.Expiry)
				m.setField("cvv", p.CVV)
				m.setField("holder", p.HolderName)
			}
		}
	}

	if len(m.fields) > 0 {
		m.fields[0].ti.Focus()
	}
}

func (m *FormModel) setField(key, val string) {
	for i := range m.fields {
		if m.fields[i].key == key {
			m.fields[i].ti.SetValue(val)
			return
		}
	}
}

func (m *FormModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m *FormModel) Update(msg tea.Msg) (*FormModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab":
			m.nextField()
		case "shift+tab":
			m.prevField()
		case "enter":
			if m.focusIndex >= len(m.fields) {
				return m, m.submit()
			}
			m.nextField()
		case "ctrl+s":
			return m, m.submit()
		case "ctrl+t":
			types := []string{"login_password", "text", "binary", "bank_card"}
			for i, t := range types {
				if t == m.secretType {
					m.secretType = types[(i+1)%len(types)]
					break
				}
			}
			m.buildFields()
		case "ctrl+c":
			return m, Navigate(ScreenList)
		}
	}

	var cmds []tea.Cmd

	if m.focusIndex < len(m.fields) {
		var cmd tea.Cmd
		m.fields[m.focusIndex].ti, cmd = m.fields[m.focusIndex].ti.Update(msg)
		cmds = append(cmds, cmd)
	} else {
		var cmd tea.Cmd
		m.comment, cmd = m.comment.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *FormModel) nextField() {
	m.focusIndex++
	if m.focusIndex > len(m.fields) {
		m.focusIndex = 0
	}
	m.updateFocus()
}

func (m *FormModel) prevField() {
	m.focusIndex--
	if m.focusIndex < 0 {
		m.focusIndex = len(m.fields)
	}
	m.updateFocus()
}

func (m *FormModel) updateFocus() {
	for i := range m.fields {
		m.fields[i].ti.Blur()
	}
	m.comment.Blur()

	if m.focusIndex < len(m.fields) {
		m.fields[m.focusIndex].ti.Focus()
	} else {
		m.comment.Focus()
	}
}

func (m *FormModel) submit() tea.Cmd {
	return func() tea.Msg {
		comment := m.comment.Value()

		var payload any
		switch m.secretType {
		case "login_password":
			payload = &model.LoginPasswordPayload{
				Login:    m.fieldVal("login"),
				Password: m.fieldVal("password"),
			}
		case "text":
			payload = &model.TextPayload{Text: m.fieldVal("text")}
		case "binary":
			path := m.fieldVal("file")
			// Fail fast on oversized files BEFORE reading into memory.
			if fi, err := os.Stat(path); err == nil && fi.Size() > model.MaxBinaryFileSize {
				return formErrMsg{err: fmt.Sprintf(
					"file is %d bytes — exceeds the %d byte limit for binary secrets",
					fi.Size(), model.MaxBinaryFileSize)}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return formErrMsg{err: "read file: " + err.Error()}
			}
			payload = &model.BinaryPayload{
				Data:     data,
				FileName: filepath.Base(path),
			}
		case "bank_card":
			payload = &model.BankCardPayload{
				Number:     m.fieldVal("number"),
				Expiry:     m.fieldVal("expiry"),
				CVV:        m.fieldVal("cvv"),
				HolderName: m.fieldVal("holder"),
			}
		}

		var err error
		if m.editSecret != nil {
			_, err = m.goph.UpdateSecret(context.Background(), m.editSecret.ID, m.editSecret.Version, payload, nil, comment)
		} else {
			_, err = m.goph.CreateSecret(context.Background(), modelSecretType(m.secretType), payload, nil, comment)
		}

		if err != nil {
			return formErrMsg{err: err.Error()}
		}
		return formOKMsg{}
	}
}

func (m *FormModel) fieldVal(key string) string {
	for _, f := range m.fields {
		if f.key == key {
			return f.ti.Value()
		}
	}
	return ""
}

func (m *FormModel) View() string {
	var b strings.Builder

	if m.editSecret != nil {
		b.WriteString(SubtitleStyle.Render("Edit Secret"))
	} else {
		b.WriteString(SubtitleStyle.Render("New Secret"))
	}
	b.WriteString("\n\n")

	typStyle := lipgloss.NewStyle().Foreground(TypeColour(m.secretType))
	b.WriteString(LabelStyle.Render("Type: ") + typStyle.Render(m.secretType) + "  " + DimStyle.Render("(ctrl+t to change)"))
	b.WriteString("\n\n")

	for i, f := range m.fields {
		b.WriteString(LabelStyle.Render(titleCase(f.key) + ":"))
		b.WriteString("\n")
		if i == m.focusIndex {
			b.WriteString(f.ti.View())
		} else {
			b.WriteString(DimStyle.Render(f.ti.View()))
		}
		b.WriteString("\n\n")
	}

	b.WriteString(LabelStyle.Render("Comment:"))
	b.WriteString("\n")
	if m.focusIndex == len(m.fields) {
		b.WriteString(m.comment.View())
	} else {
		b.WriteString(DimStyle.Render(m.comment.View()))
	}
	b.WriteString("\n\n")

	if m.err != "" {
		b.WriteString(ErrorStyle.Render("✗ " + m.err))
		b.WriteString("\n\n")
	}

	b.WriteString(DimStyle.Render("tab: next  •  enter: next/submit  •  ctrl+s: submit  •  ctrl+t: type  •  ctrl+c: cancel"))

	return b.String()
}

// Messages.
type formErrMsg struct{ err string }
type formOKMsg struct{}

func titleCase(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func modelSecretType(t string) model.SecretType {
	switch t {
	case "login_password":
		return model.SecretTypeLoginPassword
	case "text":
		return model.SecretTypeText
	case "binary":
		return model.SecretTypeBinary
	case "bank_card":
		return model.SecretTypeBankCard
	default:
		return model.SecretTypeUnspecified
	}
}
