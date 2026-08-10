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

	"github.com/puzakov/gophkeeper-exam/internal/build"
	"github.com/puzakov/gophkeeper-exam/internal/client"
	"github.com/puzakov/gophkeeper-exam/internal/config"
	"github.com/puzakov/gophkeeper-exam/internal/model"
)

var (
	cfg  *config.ClientConfig
	goph *client.GophKeeperClient
	ctx  = context.Background()
)

func main() {
	build.PrintInfo()

	cfg = loadConfig()

	rootCmd := &cobra.Command{
		Use:   "gophkeeper",
		Short: "GophKeeper — secure password manager",
		Long:  "A zero-knowledge password manager with gRPC backend. Store logins, passwords, text, binary data, and bank cards securely.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "version" {
				return nil
			}
			return connect()
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if goph != nil {
				return goph.Close()
			}
			return nil
		},
	}

	rootCmd.AddCommand(
		cmdRegister(),
		cmdLogin(),
		cmdLogout(),
		cmdAdd(),
		cmdList(),
		cmdGet(),
		cmdEdit(),
		cmdRm(),
		cmdSync(),
		cmdVersion(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadConfig() *config.ClientConfig {
	cfg := config.DefaultClientConfig()

	var serverAddr, caFile, configDir string

	root := &cobra.Command{}
	root.Flags().StringVarP(&serverAddr, "server", "s", cfg.ServerAddress, "gRPC server address")
	root.Flags().StringVar(&caFile, "ca", "", "TLS CA certificate file")
	root.Flags().StringVar(&configDir, "config-dir", cfg.ConfigDir, "config directory")
	_ = root.ParseFlags(os.Args[1:])

	flags := &config.ClientConfig{
		ServerAddress: serverAddr,
		TLSCAFile:     caFile,
		ConfigDir:     configDir,
	}

	return config.MergeClientConfig(flags, nil)
}

func connect() error {
	if err := cfg.EnsureConfigDir(); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	var err error
	goph, err = client.Connect(cfg)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}

	// Try loading saved tokens.
	if loadErr := goph.LoadTokens(); loadErr == nil && goph.IsLoggedIn() {
		return nil
	}

	// Not logged in — that's fine for register/login commands.
	return nil
}

func requireAuth() error {
	if goph == nil || !goph.IsLoggedIn() {
		return fmt.Errorf("not logged in. Run 'gophkeeper login' or 'gophkeeper register' first")
	}
	return nil
}

// Commands.

func cmdRegister() *cobra.Command {
	var login, password string

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Create a new account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if login == "" || password == "" {
				return fmt.Errorf("--login and --password are required")
			}
			if err := goph.Register(ctx, login, password); err != nil {
				return err
			}
			fmt.Println("Registered and logged in successfully.")
			fmt.Printf("User ID: %s\n", goph.UserID())
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "login")
	cmd.Flags().StringVarP(&password, "password", "p", "", "master password")
	return cmd
}

func cmdLogin() *cobra.Command {
	var login, password string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to an existing account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if login == "" || password == "" {
				return fmt.Errorf("--login and --password are required")
			}
			if err := goph.Login(ctx, login, password); err != nil {
				return err
			}
			fmt.Println("Logged in successfully.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "login")
	cmd.Flags().StringVarP(&password, "password", "p", "", "master password")
	return cmd
}

func cmdLogout() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Sign out and clear local tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			if err := goph.Logout(ctx); err != nil {
				return err
			}
			fmt.Println("Logged out.")
			return nil
		},
	}
}

func cmdAdd() *cobra.Command {
	var typ, comment, login, password, text, file, cardNumber, cardExpiry, cardCVV, cardHolder string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new secret",
		Long: `Add a new secret. Use --type to specify the kind:
  login    — login/password pair
  text     — arbitrary text
  binary   — file (path via --file)
  card     — bank card`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}

			switch typ {
			case "login":
				return addLogin(login, password, comment)
			case "text":
				return addText(text, comment)
			case "binary":
				return addBinary(file, comment)
			case "card":
				return addCard(cardNumber, cardExpiry, cardCVV, cardHolder, comment)
			default:
				return fmt.Errorf("unknown type: %s (use login, text, binary, card)", typ)
			}
		},
	}
	cmd.Flags().StringVarP(&typ, "type", "t", "", "secret type: login, text, binary, card")
	cmd.Flags().StringVar(&comment, "comment", "", "plaintext comment/label")
	cmd.Flags().StringVar(&login, "login", "", "login (for login type)")
	cmd.Flags().StringVar(&password, "password", "", "password (for login type)")
	cmd.Flags().StringVar(&text, "text", "", "text (for text type)")
	cmd.Flags().StringVar(&file, "file", "", "file path (for binary type)")
	cmd.Flags().StringVar(&cardNumber, "card-number", "", "card number")
	cmd.Flags().StringVar(&cardExpiry, "card-expiry", "", "card expiry MM/YY")
	cmd.Flags().StringVar(&cardCVV, "card-cvv", "", "card CVV")
	cmd.Flags().StringVar(&cardHolder, "card-holder", "", "card holder name")
	return cmd
}

func addLogin(login, password, comment string) error {
	p := &model.LoginPasswordPayload{Login: login, Password: password}
	sec, err := goph.CreateSecret(model.SecretTypeLoginPassword, p, nil, comment)
	if err != nil {
		return err
	}
	fmt.Printf("Secret created: %s (version %d)\n", sec.ID, sec.Version)
	return nil
}

func addText(text, comment string) error {
	p := &model.TextPayload{Text: text}
	sec, err := goph.CreateSecret(model.SecretTypeText, p, nil, comment)
	if err != nil {
		return err
	}
	fmt.Printf("Secret created: %s (version %d)\n", sec.ID, sec.Version)
	return nil
}

func addBinary(file, comment string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	p := &model.BinaryPayload{Data: data, FileName: filepath.Base(file)}
	sec, err := goph.CreateSecret(model.SecretTypeBinary, p, nil, comment)
	if err != nil {
		return err
	}
	fmt.Printf("Secret created: %s (version %d)\n", sec.ID, sec.Version)
	return nil
}

func addCard(number, expiry, cvv, holder, comment string) error {
	p := &model.BankCardPayload{
		Number:     number,
		Expiry:     expiry,
		CVV:        cvv,
		HolderName: holder,
	}
	sec, err := goph.CreateSecret(model.SecretTypeBankCard, p, nil, comment)
	if err != nil {
		return err
	}
	fmt.Printf("Secret created: %s (version %d)\n", sec.ID, sec.Version)
	return nil
}

func cmdList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			secrets, err := goph.ListSecrets()
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

func cmdGet() *cobra.Command {
	var id string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Retrieve and decrypt a secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			uid, err := uuid.Parse(id)
			if err != nil {
				return fmt.Errorf("invalid UUID: %w", err)
			}
			_, payload, meta, err := goph.GetSecret(uid)
			if err != nil {
				return err
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
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func printPayload(payload any) {
	data, _ := model.EncodePayload(payload)
	var pretty any
	_ = json.Unmarshal(data, &pretty)
	out, _ := json.MarshalIndent(pretty, "", "  ")
	fmt.Println(string(out))
}

func cmdEdit() *cobra.Command {
	var id, comment, login, password, text, cardNumber, cardExpiry, cardCVV, cardHolder string
	var expectedVersion int64

	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit an existing secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			uid, err := uuid.Parse(id)
			if err != nil {
				return fmt.Errorf("invalid UUID: %w", err)
			}

			// Get existing to determine type.
			sec, _, _, err := goph.GetSecret(uid)
			if err != nil {
				return err
			}

			var payload any
			switch sec.Type {
			case model.SecretTypeLoginPassword:
				payload = &model.LoginPasswordPayload{Login: login, Password: password}
			case model.SecretTypeText:
				payload = &model.TextPayload{Text: text}
			case model.SecretTypeBankCard:
				payload = &model.BankCardPayload{
					Number: cardNumber, Expiry: cardExpiry,
					CVV: cardCVV, HolderName: cardHolder,
				}
			default:
				return fmt.Errorf("editing type %s is not yet supported via CLI", sec.Type)
			}

			newVersion, err := goph.UpdateSecret(uid, expectedVersion, payload, nil, comment)
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
	cmd.Flags().StringVar(&password, "password", "", "new password")
	cmd.Flags().StringVar(&text, "text", "", "new text")
	cmd.Flags().StringVar(&cardNumber, "card-number", "", "new card number")
	cmd.Flags().StringVar(&cardExpiry, "card-expiry", "", "new card expiry")
	cmd.Flags().StringVar(&cardCVV, "card-cvv", "", "new card CVV")
	cmd.Flags().StringVar(&cardHolder, "card-holder", "", "new card holder")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func cmdRm() *cobra.Command {
	var id string

	cmd := &cobra.Command{
		Use:   "rm",
		Short: "Delete a secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			uid, err := uuid.Parse(id)
			if err != nil {
				return fmt.Errorf("invalid UUID: %w", err)
			}
			if err := goph.DeleteSecret(uid); err != nil {
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

func cmdSync() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Synchronise secrets with the server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			secrets, err := goph.SyncAndDecrypt(nil, nil)
			if err != nil {
				return err
			}
			fmt.Printf("Sync complete: %d secrets updated/deleted.\n", len(secrets))
			return nil
		},
	}
}

func cmdVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			build.PrintInfo()
		},
	}
}
