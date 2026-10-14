module github.com/smallerqiu/utls

go 1.26.0

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.2.6
	github.com/cloudflare/circl v1.6.5
	github.com/klauspost/compress v1.20.3
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.61.0
	golang.org/x/sys v0.49.0
)

require golang.org/x/text v0.43.0 // indirect
