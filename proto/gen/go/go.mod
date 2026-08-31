// The ONLY Go module other trees may import across seams (design Part 4 res. 4/5).
// Module-path scheme (recorded in README.md): github.com/dream-serpent/dream-serpent/<tree>.
// Holds buf-generated stubs + generated programmable fakes only — no hand-written code.
// Generation deps (google.golang.org/protobuf, google.golang.org/grpc) join this file
// with the first freeze PR's generated code, never before (offline-buildable skeleton).
module github.com/dream-serpent/dream-serpent/proto/gen/go

go 1.25.11

require (
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
)
