package clientidentity

import (
	"strings"
	"testing"
)

func TestChooseRequesterUsesVerifiedTerminalBundleForSSH(t *testing.T) {
	requester := chooseRequester([]processSnapshot{
		{executable: "ssh"},
		{executable: "zsh"},
		{
			executable: "Terminal",
			bundle: bundleMetadata{
				name:       "Terminal",
				identifier: "com.apple.Terminal",
				verified:   true,
			},
		},
	})
	if requester.Name != "Terminal" || requester.DirectClient != "ssh" {
		t.Fatalf("requester = %+v", requester)
	}
	if requester.BundleIdentifier != "com.apple.Terminal" || !requester.VerifiedBundle {
		t.Fatalf("bundle identity = %+v", requester)
	}
}

func TestChooseRequesterPrefersDebianFormOverTerminalAncestor(t *testing.T) {
	requester := chooseRequester([]processSnapshot{
		{executable: "ssh"},
		{executable: "dbf"},
		{executable: "zsh"},
		{
			executable: "Terminal",
			bundle: bundleMetadata{
				name:       "Terminal",
				identifier: "com.apple.Terminal",
				verified:   true,
			},
		},
	})
	if requester.Name != "DebianForm" || requester.DirectClient != "ssh" {
		t.Fatalf("requester = %+v", requester)
	}
	if requester.BundleIdentifier != "" || requester.VerifiedBundle {
		t.Fatalf("DebianForm fallback must not claim a verified bundle: %+v", requester)
	}
}

func TestChooseRequesterUsesVerifiedIDEAncestor(t *testing.T) {
	requester := chooseRequester([]processSnapshot{
		{executable: "ssh"},
		{executable: "git"},
		{
			executable: "Code Helper",
			bundle: bundleMetadata{
				name:       "Visual Studio Code",
				identifier: "com.microsoft.VSCode",
				verified:   true,
			},
		},
	})
	if requester.Name != "Visual Studio Code" || requester.DirectClient != "ssh" {
		t.Fatalf("requester = %+v", requester)
	}
	if requester.BundleIdentifier != "com.microsoft.VSCode" || !requester.VerifiedBundle {
		t.Fatalf("bundle identity = %+v", requester)
	}
}

func TestChooseRequesterIdentifiesYubiTouchTestSign(t *testing.T) {
	requester := chooseRequester([]processSnapshot{{
		executable: "yubitouch",
		bundle: bundleMetadata{
			name:       "YubiTouch",
			identifier: "com.github.mofelee.yubitouch",
		},
	}})
	if requester.Name != "YubiTouch" || requester.DirectClient != "YubiTouch" {
		t.Fatalf("requester = %+v", requester)
	}
	if requester.BundleIdentifier != "com.github.mofelee.yubitouch" {
		t.Fatalf("bundle identifier = %q", requester.BundleIdentifier)
	}
}

func TestChooseRequesterFallsBackWithoutUsingPathsOrControlText(t *testing.T) {
	requester := chooseRequester([]processSnapshot{{
		executable: "custom\nclient",
		path:       "/Users/example/private/custom-client",
	}})
	if requester.Name != "customclient" || requester.DirectClient != "customclient" {
		t.Fatalf("requester = %+v", requester)
	}
	if strings.Contains(requester.Name, "/Users/") || strings.Contains(requester.DirectClient, "/Users/") {
		t.Fatalf("requester leaked a path: %+v", requester)
	}
}

func TestChooseRequesterLimitsUntrustedDisplayLength(t *testing.T) {
	requester := chooseRequester([]processSnapshot{{executable: strings.Repeat("a", maxDisplayRunes+20)}})
	if got := len([]rune(requester.Name)); got != maxDisplayRunes {
		t.Fatalf("display runes = %d, want %d", got, maxDisplayRunes)
	}
}

func TestEnclosingBundleUsesOutermostApplication(t *testing.T) {
	path := "/Applications/Example.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper"
	if got := enclosingBundle(path); got != "/Applications/Example.app" {
		t.Fatalf("bundle = %q", got)
	}
}
