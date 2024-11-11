module github.com/bogdanfinn/utls

go 1.22.0

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.1.1
	github.com/cloudflare/circl v1.5.0
	github.com/klauspost/compress v1.17.11
	github.com/quic-go/quic-go v0.48.1
	golang.org/x/crypto v0.29.0
	golang.org/x/net v0.31.0
	golang.org/x/sys v0.27.0
)

require golang.org/x/text v0.20.0 // indirect
