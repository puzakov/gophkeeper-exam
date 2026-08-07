package model

// SecretType enumerates the kinds of secrets the system can store.
type SecretType int16

const (
	SecretTypeUnspecified   SecretType = 0
	SecretTypeLoginPassword SecretType = 1
	SecretTypeText          SecretType = 2
	SecretTypeBinary        SecretType = 3
	SecretTypeBankCard      SecretType = 4
)

// String returns a human-readable name for the secret type.
func (t SecretType) String() string {
	switch t {
	case SecretTypeLoginPassword:
		return "login_password"
	case SecretTypeText:
		return "text"
	case SecretTypeBinary:
		return "binary"
	case SecretTypeBankCard:
		return "bank_card"
	default:
		return "unknown"
	}
}

// Valid reports whether t is a recognised secret type.
func (t SecretType) Valid() bool {
	return t >= SecretTypeLoginPassword && t <= SecretTypeBankCard
}
