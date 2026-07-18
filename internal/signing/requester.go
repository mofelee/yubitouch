package signing

// Requester is an immutable, display-only snapshot captured from the local
// Agent connection. It intentionally excludes PIDs, executable paths, argv,
// remote hosts, and other values that must not reach state or logs.
type Requester struct {
	Name             string
	DirectClient     string
	BundleIdentifier string
	VerifiedBundle   bool
}
