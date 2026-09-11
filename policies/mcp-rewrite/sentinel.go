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

package mcprewrite

import (
	"encoding/base64"
	"errors"
	"strings"
)

const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

// errMalformedSentinel marks a value that announced itself as sentinel-encoded but whose
// payload is not decodable base64.
var errMalformedSentinel = errors.New("malformed base64 sentinel value")

// decodeSentinel unwraps the "=?base64?<standard-base64>?=" form MCP defines for header values
// that cannot be written as visible ASCII, returning anything else unchanged. The markers are
// lowercase and case-sensitive, and the spec requires the wrapping even for a plain value that
// would collide with the pattern — so sentinel form always means encoded.
func decodeSentinel(value string) (string, error) {
	if !strings.HasPrefix(value, sentinelPrefix) || !strings.HasSuffix(value, sentinelSuffix) {
		return value, nil
	}
	// The two markers share the trailing "?=", so "=?base64?=" satisfies both checks while
	// carrying no payload. Without this guard the slice below runs out of range.
	if len(value) < len(sentinelPrefix)+len(sentinelSuffix) {
		return "", errMalformedSentinel
	}
	raw, err := base64.StdEncoding.DecodeString(value[len(sentinelPrefix) : len(value)-len(sentinelSuffix)])
	if err != nil {
		return "", errMalformedSentinel
	}
	return string(raw), nil
}

// encodeSentinel wraps a value for transport in an Mcp-Name header, inverting the
// decodeSentinel in mcp_facts.go. This policy is the only MCP policy that writes a mirrored
// header rather than only reading one, so it is the only one that needs this direction.
//
// The rewrite target comes from operator configuration and is unconstrained: it may hold
// non-ASCII, or the control characters a header injection would use. Writing it raw would be
// both a conformance bug and an injection vector.
func encodeSentinel(value string) string {
	if !needsSentinel(value) {
		return value
	}
	return sentinelPrefix + base64.StdEncoding.EncodeToString([]byte(value)) + sentinelSuffix
}

// needsSentinel reports whether a value has to be wrapped to travel in a header field.
//
// Two separate reasons, and the second is easy to miss. A value outside visible ASCII cannot
// be written literally. A value that merely looks like the sentinel form must also be wrapped,
// because the spec requires the wrapping whenever a plain value would collide with the
// pattern — otherwise a reader decoding it would recover something the operator never wrote.
//
// Stricter than the inbound isValidFieldValue, which permits space and tab: those are legal
// octets in a received field value, but a name carrying them is not safely representable and
// is encoded rather than passed through.
func needsSentinel(value string) bool {
	if strings.HasPrefix(value, sentinelPrefix) && strings.HasSuffix(value, sentinelSuffix) {
		return true
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 0x21 || c > 0x7E {
			return true
		}
	}
	return false
}
