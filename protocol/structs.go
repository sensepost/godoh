package protocol

// FileTransport defines properties, as well as the data for a file.
type FileTransport struct {
	Data   []byte
	Size   int64
	Shasum string
}
