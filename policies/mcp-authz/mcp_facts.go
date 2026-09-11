/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package mcpauthz

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Request headers MCP 2026-07-28 mirrors the operation into, and the body-derived
// attributes the gateway's MCP resolver publishes.
const (
	headerProtocolVersion = "MCP-Protocol-Version"
	headerMcpMethod       = "Mcp-Method"
	headerMcpName         = "Mcp-Name"

	attrBodyMethod         = "mcp.body.method"
	attrBodyCapabilityName = "mcp.body.capability.name"
	attrBodyJSONRPCID      = "mcp.body.jsonrpc.id"
	attrBodyUnusable       = "mcp.body.unusable"

	// attrBodyPresent is published by the resolver for any body it received, readable or
	// not — including alongside attrBodyUnusable, since whether bytes arrived and whether
	// they could be read are different questions. Its absence therefore means no body.
	attrBodyPresent = "mcp.body.present"

	// specVersionModern is the first revision to mirror values into headers. Versions are
	// ISO-8601 dates, so string comparison is chronological.
	specVersionModern = "2026-07-28"

	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

// errMalformedSentinel marks a value that announced itself as sentinel-encoded but whose
// payload is not decodable base64.
var errMalformedSentinel = errors.New("malformed base64 sentinel value")

// mcpRequestFacts is what one MCP request can be known to be: the operation it invokes, the
// capability it targets, the id a rejection echoes back, and the two circumstances that
// decide what an empty Method means.
type mcpRequestFacts struct {
	// RequestID is the id as the JSON token it arrived as — 7 for a number, "7" with its quotes
	// for a string — so a rejection echoes back what the client sent and its correlation
	// matches. Always either valid JSON or empty, and empty renders as null.
	RequestID json.RawMessage

	Method string
	Name   string

	// IsModernRequest reports that the request declared MCP 2026-07-28 or later, which is
	// what makes Method and Name come from the mirrored headers rather than the resolver's
	// reading of the body. Recorded rather than left for a caller to re-test, so a call site
	// deciding what an empty Method means cannot drift from the branch that produced it.
	IsModernRequest bool

	// IsRequestBodyPresent reports that a body reached the resolver — nothing about whether
	// it could be read, or what it said. Read straight off mcp.body.present, which the
	// resolver publishes for any body it received, unreadable ones included.
	IsRequestBodyPresent bool
}

// HasMethod reports whether the request named a JSON-RPC method — from the resolver, or from the
// mirrored header on a modern request.
//
// False does NOT mean the operation is unknown. A body read successfully may simply have named
// none, which is authoritative: a client-posted JSON-RPC response answering a server-initiated
// sampling call carries an id and a result and no method. Separating "named none" from "never
// learned" takes IsRequestBodyPresent and IsModernRequest as well; see mcp-auth's
// OnRequestHeaders. A policy that restricts rather than exempts usually needs only this one.
func (f mcpRequestFacts) HasMethod() bool { return f.Method != "" }

// mcpFacts reads the operation this request invokes: from the mirrored headers on MCP
// 2026-07-28 or later, and from the resolver's attributes otherwise. For the header phase,
// which has no body — a caller holding a buffered body should parse that instead.
//
// Duplicated per policy: separate Go modules, no shared package. Every copy is byte-identical
// apart from its package clause — keep it that way, so a reader who has seen one has seen all of
// them. Fix a bug in every copy, and add a fact to every copy.
//
// Not every consumer reads every field, and that is expected: mcp-ratelimit is the only one that
// reads RequestID, and IsRequestBodyPresent exists so a call site can tell an operation it never
// learned from one a body named none of — mcp-auth reads it; see its OnRequestHeaders.
func mcpFacts(headers *policy.Headers, shared *policy.SharedContext) mcpRequestFacts {
	attrs := resolutionAttributes(shared)

	facts := mcpRequestFacts{
		IsModernRequest:      isModernRequest(headers),
		IsRequestBodyPresent: attrs.Get(attrBodyPresent) == "true",
	}

	// The body is the fallback in both eras, never the override. A modern request is read
	// from the mirrored headers because that is what the revision defines them for, but a
	// header the client did not send, or sent in a form that will not decode, carries no
	// claim to fall back from — and the resolver has already read the body, so the answer is
	// in hand.
	//
	// A header that IS present and decodable wins even when it disagrees with the body.
	// Detecting that disagreement is mcp-validation's job; attach it ahead of this policy.
	facts.Method = attrs.Get(attrBodyMethod)
	facts.Name = attrs.Get(attrBodyCapabilityName)

	if facts.IsModernRequest {
		if method := firstHeader(headers, headerMcpMethod); method != "" {
			facts.Method = method
		}
		if raw := firstHeader(headers, headerMcpName); raw != "" {
			if decoded, err := decodeSentinel(raw); err == nil {
				facts.Name = decoded
			}
		}
	}

	// Outside the era branch: no revision mirrors the id into a header, so the attribute is
	// the one source in both. It is published independently of the method, so a body that
	// named no operation still yields the id its rejection has to echo.
	//
	// The validity check is defensive and mirrors the MCP validation policy's jsonRPCID: a
	// mangled token reaching json.Marshal fails the whole envelope rather than just the id.
	// An absent attribute is not valid JSON either, so one test covers both.
	if raw := attrs.Get(attrBodyJSONRPCID); json.Valid([]byte(raw)) {
		facts.RequestID = json.RawMessage(raw)
	}

	return facts
}

// resolutionAttributes returns what the resolver published for this request, or a zero value
// whose Get answers "" for every key. One nil check for the file: SharedContext is absent only
// on a defensive path, and every reader below wants "no attributes" rather than a panic.
func resolutionAttributes(shared *policy.SharedContext) policy.ResolutionAttributes {
	if shared == nil {
		return policy.ResolutionAttributes{}
	}
	return shared.ResolutionAttributes
}

// unusableBodyReason returns why the resolver could not read the request body, or "" if it
// read it or never ran. Any reason means the gateway and the server may read those bytes
// differently, so the request is rejected rather than governed.
func unusableBodyReason(shared *policy.SharedContext) string {
	return resolutionAttributes(shared).Get(attrBodyUnusable)
}

// isModernRequest reports whether the request declares a revision that mirrors the
// operation into headers. An absent version header is legacy — that is what every client
// sent before 2026-07-28.
func isModernRequest(headers *policy.Headers) bool {
	return firstHeader(headers, headerProtocolVersion) >= specVersionModern
}

// firstHeader returns a header's first value, or "" when absent.
func firstHeader(headers *policy.Headers, name string) string {
	values := headers.Get(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// decodeSentinel unwraps the "=?base64?<standard-base64>?=" form MCP defines for header
// values that cannot be written as visible ASCII, returning anything else unchanged. The
// markers are lowercase and case-sensitive, and the spec requires the wrapping even for a
// plain value that would collide with the pattern — so sentinel form always means encoded.
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
