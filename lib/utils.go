package lib

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	mrand "math/rand"
)

// GobPress will gob encode and compress a struct
func GobPress(s interface{}, data io.Writer) error {

	j, err := json.Marshal(s)
	if err != nil {
		return err
	}

	// Encrypt the data
	enc, err := Encrypt(j)
	if err != nil {
		return err
	}

	return ZlibWrite(data, enc)
}

// UngobUnpress will gob decode and decompress a struct
func UngobUnpress(s interface{}, data []byte) error {

	dcData := bytes.Buffer{}
	if err := UnzlibWrite(&dcData, data); err != nil {
		return err
	}

	// Decrypt the data
	decryptData, err := Decrypt(dcData.Bytes())
	if err != nil {
		return err
	}

	if err := json.Unmarshal(decryptData, &s); err != nil {
		return err
	}

	return nil
}

// ZlibWrite data to a Writer
func ZlibWrite(w io.Writer, data []byte) error {
	wr, err := zlib.NewWriterLevel(w, flate.BestCompression)
	defer wr.Close()
	wr.Write(data)

	return err
}

// UnzlibWrite data to a Writer
func UnzlibWrite(w io.Writer, data []byte) error {
	zr, err := zlib.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	data, err = ioutil.ReadAll(zr)
	if err != nil {
		return err
	}
	w.Write(data)

	return nil
}

// ByteSplit will split []byte into chunks of lim
func ByteSplit(buf []byte, lim int) [][]byte {
	var chunk []byte

	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}

	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}

	return chunks
}

// RandomString just generates a crappy random string.
// This is not a crypto related function, so "how random" really doesnt matter.
func RandomString(strlen int) string {

	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, strlen)
	for i := range result {
		result[i] = chars[mrand.Intn(len(chars))]
	}
	return string(result)
}

// Encrypt will encrypt a byte stream
// https://golang.org/pkg/crypto/cipher/#NewCFBEncrypter
func Encrypt(plaintext []byte) ([]byte, error) {
	key, _ := hex.DecodeString(cryptKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// Decrypt will decrypt a byte stream
// https://golang.org/pkg/crypto/cipher/#example_NewCFBDecrypter
func Decrypt(ciphertext []byte) ([]byte, error) {
	key, _ := hex.DecodeString(cryptKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("Cipher text too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}
