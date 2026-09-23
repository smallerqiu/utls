module github.com/smallerqiu/utls

go 1.26.0

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.2.4
	github.com/cloudflare/circl v1.6.5
	github.com/klauspost/compress v1.20.0
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/sys v0.48.0
)

require golang.org/x/text v0.42.0 // indirect
