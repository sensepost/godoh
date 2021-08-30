package lib

// AES key used to encrypt data blobs in communications
// $ openssl rand -hex 16

var cryptKey = `aacf6ed6e4b999a6338d5a025350ea5a`

func SetAESKey(key string) {
	cryptKey = key
}
