//go:build darwin

/*
Copyright NetFoundry Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testutil

// macOS has no pure-Go path to keychain keys

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static int keychainKeyExists(const char *name) {
    CFDataRef tag = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)name, (CFIndex)strlen(name));
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
    CFDictionaryAddValue(q, kSecClass, kSecClassKey);
    CFDictionaryAddValue(q, kSecAttrApplicationTag, tag);
    CFDictionaryAddValue(q, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    OSStatus r = SecItemCopyMatching(q, NULL);
    CFRelease(q);
    CFRelease(tag);
    return r == errSecSuccess ? 1 : 0;
}

static int keychainKeyRemove(const char *name) {
    CFDataRef tag = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)name, (CFIndex)strlen(name));
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
    CFDictionaryAddValue(q, kSecClass, kSecClassKey);
    CFDictionaryAddValue(q, kSecAttrApplicationTag, tag);
    CFDictionaryAddValue(q, kSecMatchLimit, kSecMatchLimitAll);
    OSStatus r = SecItemDelete(q);
    CFRelease(q);
    CFRelease(tag);
    return (r == errSecSuccess || r == errSecItemNotFound) ? 0 : (int)r;
}
*/
import "C"

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func KeychainKeyExists(_ *testing.T, keyRef string) bool {
	name := C.CString(strings.TrimPrefix(keyRef, "keychain:"))
	defer C.free(unsafe.Pointer(name))
	return C.keychainKeyExists(name) == 1
}

func RemoveKeychainKey(t *testing.T, keyRef string) {
	name := C.CString(strings.TrimPrefix(keyRef, "keychain:"))
	defer C.free(unsafe.Pointer(name))
	rc := int(C.keychainKeyRemove(name))
	require.Zero(t, rc, "SecItemDelete failed for %q: OSStatus %d", keyRef, rc)
}
