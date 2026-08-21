// GophKeeper client — CLI for secure password management.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/puzakov/gophkeeper-exam/internal/build"
	"github.com/puzakov/gophkeeper-exam/internal/client"
	"github.com/puzakov/gophkeeper-exam/internal/config"
	"github.com/puzakov/gophkeeper-exam/internal/model"
	"github.com/puzakov/gophkeeper-exam/internal/term"
	"github.com/puzakov/gophkeeper-exam/internal/tui"
)

// App encapsulates the CLI application state. All dependencies are passed
// explicitly through it instead of package-level globals.
type App struct {
	cfg  *config.ClientConfig
	goph *client.GophKeeperClient
	ctx  context.Context
}

func main() {
	build.PrintInfo()

	app := &App{ctx: context.Background()}
	app.cfg = app.loadConfig()

	rootCmd := app.rootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// rootCommand builds the root cobra command with all subcommands.
func (a *App) rootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "gophkeeper",
		Short: "GophKeeper — secure password manager",
		Long:  "A zero-knowledge password manager with gRPC backend. Store logins, passwords, text, binary data, and bank cards securely.\n\nRun without a subcommand to launch the interactive TUI.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "version" || cmd.Name() == "gophkeeper" {
				return nil
			}
			return a.connect()
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if a.goph != nil {
				return a.goph.Close()
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Default: launch TUI.
			if err := a.connect(); err != nil {
				return err
			}
			defer a.goph.Close()

			app := tui.NewApp(a.goph)
			p := tea.NewProgram(app, tea.WithAltScreen())
			_, err := p.Run()
			return err
		},
	}

	rootCmd.AddCommand(
		a.cmdRegister(),
		a.cmdLogin(),
		a.cmdLogout(),
		a.cmdAdd(),
		a.cmdList(),
		a.cmdGet(),
		a.cmdEdit(),
		a.cmdRm(),
		a.cmdSync(),
		a.cmdTui(),
		a.cmdVersion(),
	)

	return rootCmd
}

func (a *App) loadConfig() *config.ClientConfig {
	defaults := config.DefaultClientConfig()

	var serverAddr, caFile, configDir string

	root := &cobra.Command{}
	root.Flags().StringVarP(&serverAddr, "server", "s", defaults.ServerAddress, "gRPC server address")
	root.Flags().StringVar(&caFile, "ca", "", "TLS CA certificate file")
	root.Flags().StringVar(&configDir, "config-dir", defaults.ConfigDir, "config directory")
	_ = root.ParseFlags(os.Args[1:])

	flags := &config.ClientConfig{
		ServerAddress: serverAddr,
		TLSCAFile:     caFile,
		ConfigDir:     configDir,
	}

	return config.MergeClientConfig(flags, nil)
}

func (a *App) connect() error {
	if err := a.cfg.EnsureConfigDir(); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	var err error
	a.goph, err = client.Connect(a.cfg)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}

	// Try loading saved tokens.
	if loadErr := a.goph.LoadTokens(); loadErr == nil && a.goph.IsLoggedIn() {
		// The monitor probes become active once the DEK is available
		// (after login/unlock); until then probe() is a no-op.
		a.goph.StartConnectivityMonitor(a.ctx)
		return nil
	}

	// Not logged in — that's fine for register/login commands.
	return nil
}

func (a *App) requireAuth() error {
	if a.goph == nil || !a.goph.IsLoggedIn() {
		return fmt.Errorf("not logged in. Run 'gophkeeper login' or 'gophkeeper register' first")
	}
	return nil
}

// Commands.

func (a *App) cmdRegister() *cobra.Command {
	var login string

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Create a new account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if login == "" {
				return fmt.Errorf("--login is required")
			}
			password, err := term.ReadPasswordWithConfirm("Master password: ")
			if err != nil {
				return err
			}
			if err := a.goph.Register(a.ctx, login, password); err != nil {
				return err
			}
			fmt.Println("Registered and logged in successfully.")
			fmt.Printf("User ID: %s\n", a.goph.UserID())
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "login")
	return cmd
}

func (a *App) cmdLogin() *cobra.Command {
	var login string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to an existing account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if login == "" {
				return fmt.Errorf("--login is required")
			}
			password, err := term.ReadPassword("Master password: ")
			if err != nil {
				return err
			}
			if err := a.goph.Login(a.ctx, login, password); err != nil {
				return err
			}
			fmt.Println("Logged in successfully.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "login")
	return cmd
}

func (a *App) cmdLogout() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Sign out and clear local tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireAuth(); err != nil {
				return err
			}
			if err := a.goph.Logout(a.ctx); err != nil {
				return err
			}
			fmt.Println("Logged out.")
			return nil
		},
	}
}

func (a *App) cmdAdd() *cobra.Command {
	var typ, comment, login, text, file, cardNumber, cardExpiry, cardHolder string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new secret",
		Long: `Add a new secret. Use --type to specify the kind:
  login    — login/password pair (password prompted securely)
  text     — arbitrary text
  binary   — file (path via --file)
  card     — bank card (CVV prompted securely)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireAuth(); err != nil {
				return err
			}

			switch typ {
			case "login":
				password, err := term.ReadPassword("Password: ")
				if err != nil {
					return err
				}
				return a.addLogin(login, password, comment)
			case "text":
				return a.addText(text, comment)
			case "binary":
				return a.addBinary(file, comment)
			case "card":
				cvv, err := term.ReadPassword("CVV: ")
				if err != nil {
					return err
				}
				return a.addCard(cardNumber, cardExpiry, cvv, cardHolder, comment)
			default:
				return fmt.Errorf("unknown type: %s (use login, text, binary, card)", typ)
			}
		},
	}
	cmd.Flags().StringVarP(&typ, "type", "t", "", "secret type: login, text, binary, card")
	cmd.Flags().StringVar(&comment, "comment", "", "plaintext comment/label")
	cmd.Flags().StringVar(&login, "login", "", "login (for login type)")
	cmd.Flags().StringVar(&text, "text", "", "text (for text type)")
	cmd.Flags().StringVar(&file, "file", "", "file path (for binary type)")
	cmd.Flags().StringVar(&cardNumber, "card-number", "", "card number")
	cmd.Flags().StringVar(&cardExpiry, "card-expiry", "", "card expiry MM/YY")
	cmd.Flags().StringVar(&cardHolder, "card-holder", "", "card holder name")
	return cmd
}

func (a *App) addLogin(login, password, comment string) error {
	p := &model.LoginPasswordPayload{Login: login, Password: password}
	sec, err := a.goph.CreateSecret(a.ctx, model.SecretTypeLoginPassword, p, nil, comment)
	if err != nil {
		return err
	}
	fmt.Printf("Secret created: %s (version %d)\n", sec.ID, sec.Version)
	return nil
}

func (a *App) addText(text, comment string) error {
	p := &model.TextPayload{Text: text}
	sec, err := a.goph.CreateSecret(a.ctx, model.SecretTypeText, p, nil, comment)
	if err != nil {
		return err
	}
	fmt.Printf("Secret created: %s (version %d)\n", sec.ID, sec.Version)
	return nil
}

func (a *App) addBinary(file, comment string) error {
	// Fail fast on oversized files BEFORE reading them into memory.
	if err := checkFileSize(file); err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	p := &model.BinaryPayload{Data: data, FileName: filepath.Base(file)}
	sec, err := a.goph.CreateSecret(a.ctx, model.SecretTypeBinary, p, nil, comment)
	if err != nil {
		return err
	}
	fmt.Printf("Secret created: %s (version %d)\n", sec.ID, sec.Version)
	return nil
}

// checkFileSize rejects files larger than the binary secret limit.
func checkFileSize(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	if fi.Size() > model.MaxBinaryFileSize {
		return fmt.Errorf("file %s is %d bytes — exceeds the %d byte limit for binary secrets",
			path, fi.Size(), model.MaxBinaryFileSize)
	}
	return nil
}

func (a *App) addCard(number, expiry, cvv, holder, comment string) error {
	p := &model.BankCardPayload{
		Number:     number,
		Expiry:     expiry,
		CVV:        cvv,
		HolderName: holder,
	}
	sec, err := a.goph.CreateSecret(a.ctx, model.SecretTypeBankCard, p, nil, comment)
	if err != nil {
		return err
	}
	fmt.Printf("Secret created: %s (version %d)\n", sec.ID, sec.Version)
	return nil
}

func (a *App) cmdList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireAuth(); err != nil {
				return err
			}
			secrets, err := a.goph.ListSecrets(a.ctx)
			if err != nil {
				return err
			}
			if len(secrets) == 0 {
				fmt.Println("No secrets stored yet.")
				return nil
			}
			fmt.Printf("%-36s  %-12s  %s\n", "ID", "TYPE", "COMMENT")
			fmt.Println("------------------------------------  ------------  ----------------------")
			for _, s := range secrets {
				fmt.Printf("%-36s  %-12s  %s\n", s.ID.String(), s.Type.String(), s.Comment)
			}
			return nil
		},
	}
}

func (a *App) cmdGet() *cobra.Command {
	var id, output string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Retrieve and decrypt a secret. Use --output to save binary/text to a file.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireAuth(); err != nil {
				return err
			}
			uid, err := uuid.Parse(id)
			if err != nil {
				return fmt.Errorf("invalid UUID: %w", err)
			}
			_, payload, meta, err := a.goph.GetSecret(a.ctx, uid)
			if err != nil {
				return err
			}

			// Save to file if --output is set.
			if output != "" {
				return savePayloadToFile(payload, output)
			}

			printPayload(payload)
			if len(meta) > 0 {
				fmt.Println("\nMetadata:")
				for k, v := range meta {
					fmt.Printf("  %s: %s\n", k, v)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&id, "id", "i", "", "secret ID (UUID)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "save decrypted data to file")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func savePayloadToFile(payload any, path string) error {
	var data []byte
	var displayName string

	switch p := payload.(type) {
	case *model.BinaryPayload:
		data = p.Data
		displayName = p.FileName
	case *model.TextPayload:
		data = []byte(p.Text)
	case *model.LoginPasswordPayload:
		return fmt.Errorf("login/password secrets cannot be saved to file; omit --output to view")
	case *model.BankCardPayload:
		return fmt.Errorf("bank card secrets cannot be saved to file; omit --output to view")
	default:
		return fmt.Errorf("unknown payload type")
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	if displayName != "" {
		fmt.Printf("Saved %q (%d bytes) → %s\n", displayName, len(data), path)
	} else {
		fmt.Printf("Saved %d bytes → %s\n", len(data), path)
	}
	return nil
}

func printPayload(payload any) {
	switch p := payload.(type) {
	case *model.BinaryPayload:
		fmt.Printf("File: %s  (%d bytes)\n", p.FileName, len(p.Data))
		fmt.Println("Use -o/--output <path> to save to a file.")
	case *model.TextPayload:
		fmt.Println(p.Text)
	default:
		data, _ := model.EncodePayload(payload)
		var pretty any
		_ = json.Unmarshal(data, &pretty)
		out, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Println(string(out))
	}
}

func (a *App) cmdEdit() *cobra.Command {
	var id, comment, login, text, cardNumber, cardExpiry, cardHolder string
	var expectedVersion int64

	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit an existing secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireAuth(); err != nil {
				return err
			}
			uid, err := uuid.Parse(id)
			if err != nil {
				return fmt.Errorf("invalid UUID: %w", err)
			}

			// Get existing to determine type.
			sec, _, _, err := a.goph.GetSecret(a.ctx, uid)
			if err != nil {
				return err
			}

			var payload any
			switch sec.Type {
			case model.SecretTypeLoginPassword:
				password, err := term.ReadPassword("New password: ")
				if err != nil {
					return err
				}
				payload = &model.LoginPasswordPayload{Login: login, Password: password}
			case model.SecretTypeText:
				payload = &model.TextPayload{Text: text}
			case model.SecretTypeBankCard:
				cvv, err := term.ReadPassword("New CVV: ")
				if err != nil {
					return err
				}
				payload = &model.BankCardPayload{
					Number: cardNumber, Expiry: cardExpiry,
					CVV: cvv, HolderName: cardHolder,
				}
			default:
				return fmt.Errorf("editing type %s is not yet supported via CLI", sec.Type)
			}

			newVersion, err := a.goph.UpdateSecret(a.ctx, uid, expectedVersion, payload, nil, comment)
			if err != nil {
				return err
			}
			fmt.Printf("Secret updated: version %d\n", newVersion)
			return nil
		},
	}
	cmd.Flags().StringVarP(&id, "id", "i", "", "secret ID (UUID)")
	cmd.Flags().Int64Var(&expectedVersion, "version", 0, "expected current version (optimistic locking)")
	cmd.Flags().StringVar(&comment, "comment", "", "new comment")
	cmd.Flags().StringVar(&login, "login", "", "new login")
	cmd.Flags().StringVar(&text, "text", "", "new text")
	cmd.Flags().StringVar(&cardNumber, "card-number", "", "new card number")
	cmd.Flags().StringVar(&cardExpiry, "card-expiry", "", "new card expiry")
	cmd.Flags().StringVar(&cardHolder, "card-holder", "", "new card holder")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func (a *App) cmdRm() *cobra.Command {
	var id string

	cmd := &cobra.Command{
		Use:   "rm",
		Short: "Delete a secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireAuth(); err != nil {
				return err
			}
			uid, err := uuid.Parse(id)
			if err != nil {
				return fmt.Errorf("invalid UUID: %w", err)
			}
			if err := a.goph.DeleteSecret(a.ctx, uid); err != nil {
				return err
			}
			fmt.Printf("Secret %s deleted.\n", uid)
			return nil
		},
	}
	cmd.Flags().StringVarP(&id, "id", "i", "", "secret ID (UUID)")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func (a *App) cmdSync() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Synchronise secrets with the server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireAuth(); err != nil {
				return err
			}
			secrets, err := a.goph.SyncAndDecrypt(a.ctx, nil, nil)
			if err != nil {
				return err
			}
			fmt.Printf("Sync complete: %d secrets updated/deleted.\n", len(secrets))
			return nil
		},
	}
}

func (a *App) cmdTui() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive terminal UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.connect(); err != nil {
				return err
			}
			if a.goph != nil {
				defer a.goph.Close()
			}

			app := tui.NewApp(a.goph)
			p := tea.NewProgram(app, tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				return fmt.Errorf("TUI error: %w", err)
			}
			return nil
		},
	}
}

func (a *App) cmdVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			build.PrintInfo()
		},
	}
}
