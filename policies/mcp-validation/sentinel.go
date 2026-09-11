/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package mcpvalidation

import (
	"encoding/base64"
	"errors"
	"strings"
)

// Sentinel markers from the MCP 2026-07-28 streamable-HTTP transport, section
// "Value Encoding". They are lowercase and case-sensitive: "=?BASE64?…?=" is a literal
// value, not an encoded one.
const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

// errMalformedSentinel is returned when a value announces itself as sentinel-encoded but
// its payload is not decodable Base64. It is a client error, not a server one — the value
// travelled on the wire in a form the spec does not define.
var errMalformedSentinel = errors.New("value is in sentinel form but its payload is not valid base64")

// decodeSentinel returns the real value behind an Mcp-Name or Mcp-Param header.
//
// The spec allows a value that is not safely representable as visible ASCII to be wrapped
// as "=?base64?<standard-base64>?=", and *requires* the same wrapping when a plain value
// would otherwise collide with that pattern. So a value in sentinel form is always encoded
// and a value not in sentinel form is always literal — there is no ambiguous case to guess.
//
// It names intermediaries directly: "Servers and intermediaries that need to inspect these
// values MUST decode them… MUST decode before comparing." Comparing an encoded header
// against a decoded body value is exactly the mistake this exists to prevent.
//
// A value that is not in sentinel form is returned unchanged, with no error.
func decodeSentinel(value string) (string, error) {
	// Both markers must be present. A value that merely starts with the prefix is not in
	// sentinel form, and treating it as such would corrupt a legitimate literal.
	if !strings.HasPrefix(value, sentinelPrefix) || !strings.HasSuffix(value, sentinelSuffix) {
		return value, nil
	}
	// Guard the degenerate overlap: "=?base64?=" satisfies both HasPrefix and HasSuffix
	// while carrying no payload, because the two markers share the trailing "?=".
	if len(value) < len(sentinelPrefix)+len(sentinelSuffix) {
		return "", errMalformedSentinel
	}

	encoded := value[len(sentinelPrefix) : len(value)-len(sentinelSuffix)]
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errMalformedSentinel
	}
	return string(raw), nil
}

// isValidFieldValue reports whether a raw header value uses only the octets RFC 9110
// permits in a field value: visible ASCII (0x21–0x7E), space (0x20) and horizontal tab
// (0x09).
//
// It must be applied to the value as it arrived, *before* any sentinel decoding, for two
// reasons. The raw value is the octet sequence that actually travelled in the header field,
// so it is the only thing RFC 9110 constrains. And the decoded payload is *allowed* to fall
// outside that set — carrying such a value is the entire purpose of the sentinel wrapper —
// so checking after decoding would reject values the spec explicitly permits.
//
// Decoded bytes are safe to leave unchecked here because they are only ever compared
// against a body value; this policy never writes one back out as a header.
func isValidFieldValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\t' || c == ' ' || (c >= 0x21 && c <= 0x7E) {
			continue
		}
		return false
	}
	return true
}
