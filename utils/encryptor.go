package utils

type ModelEncyptorInterface interface {
	Encrypt(data string) (string, error)
	Decrypt(data string) (string, error)
}
