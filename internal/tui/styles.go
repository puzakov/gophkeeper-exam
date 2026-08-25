// Package tui implements the terminal user interface for GophKeeper.
package tui

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	// Base colours.
	primary   = lipgloss.Color("#7C3AED") // violet
	accent    = lipgloss.Color("#06B6D4") // cyan
	success   = lipgloss.Color("#10B981") // green
	warning   = lipgloss.Color("#F59E0B") // amber
	danger    = lipgloss.Color("#EF4444") // red
	subtle    = lipgloss.Color("#6B7280") // grey
	highlight = lipgloss.Color("#F9FAFB") // near-white

	// Title style.
	TitleStyle = lipgloss.NewStyle().
			Foreground(primary).
			Bold(true).
			MarginBottom(1)

	// Subtitle style.
	SubtitleStyle = lipgloss.NewStyle().
			Foreground(accent).
			Bold(true)

	// Help text at the bottom.
	HelpStyle = lipgloss.NewStyle().
			Foreground(subtle).
			MarginTop(1)

	// Input label.
	LabelStyle = lipgloss.NewStyle().
			Foreground(accent).
			Bold(true)

	// Error message.
	ErrorStyle = lipgloss.NewStyle().
			Foreground(danger).
			Bold(true)

	// Success message.
	SuccessStyle = lipgloss.NewStyle().
			Foreground(success).
			Bold(true)

	// Secret list item.
	ItemStyle = lipgloss.NewStyle().
			PaddingLeft(1)

	// Selected item.
	SelectedStyle = lipgloss.NewStyle().
			PaddingLeft(1).
			Foreground(highlight).
			Background(primary)

	// Info / dimmed text.
	DimStyle = lipgloss.NewStyle().
			Foreground(subtle)

	// Active tab / filter.
	ActiveTabStyle = lipgloss.NewStyle().
			Foreground(highlight).
			Background(primary).
			Padding(0, 1)

	InactiveTabStyle = lipgloss.NewStyle().
				Foreground(subtle).
				Padding(0, 1)
)

// TypeColour returns a colour for the given secret type name.
func TypeColour(t string) lipgloss.Color {
	switch t {
	case "login_password":
		return accent
	case "text":
		return success
	case "binary":
		return warning
	case "bank_card":
		return danger
	default:
		return subtle
	}
}
