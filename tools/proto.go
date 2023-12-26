package tools

type Flag uint32

const (
	RequestCert   Flag = iota // Request certificate:
	ReRequestCert             // Return certificate
	Open                      // Establish a long connection:
	SendFile                  // Send file:
	GetFileList               // Get the file directory:
	GetFile                   // Get file:
	DeleteFile                // Delete file:
)
const (
	MaxContentSize = 104857 //1MB
)

type DataPacket struct {
	Flag          Flag   `json:"flag"`
	Certname      string `json:"certname"`
	FileName      string `json:"file_name"`
	PacketCount   uint32 `json:"packet_count"`
	CurrentPacket uint32 `json:"current_packet"`
	PacketSize    uint32 `json:"packet_size"`
	Nowsize       uint32 `json:"nowsize"`
	Content       string `json:"content"`
	Signature     string `json:"EOF"`
}
