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

// Package mcpvalidation validates MCP requests at the gateway: the request body on every
// request, and the mirrored HTTP headers on requests that declare a modern protocol
// version.
//
// MCP 2026-07-28 mirrors the JSON-RPC method and capability name into Mcp-Method and
// Mcp-Name so an intermediary can enforce policy without parsing the payload. That is only
// safe if the two agree: a caller could otherwise present one method in a header — which
// the other MCP policies enforce on — and a different one in the body, which is what the
// server actually executes. The spec makes checking that agreement the server's
// obligation; this policy lets a gateway operator do it at the edge instead of trusting
// the backend to.
//
// It parses nothing. The route's operation resolver reads the body once, before any policy
// runs, and publishes both what it found and — when it could not read the body at all —
// why. This policy turns those findings into JSON-RPC errors and compares them against the
// headers.
//
// It does not restrict which protocol versions a proxy accepts. That is a separate concern
// and a separate policy; this one takes no configuration at all.
package mcpvalidation

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Request headers defined by the 2026-07-28 streamable-HTTP transport.
const (
	headerProtocolVersion = "MCP-Protocol-Version"
	headerMcpMethod       = "Mcp-Method"
	headerMcpName         = "Mcp-Name"
)

// Resolution attributes published by the engine's MCP resolver. Every key is body-derived;
// the mcp.body. prefix is what keeps a header value and a body value distinguishable at the
// call sites that hold both.
const (
	attrBodyMethod          = "mcp.body.method"
	attrBodyCapabilityName  = "mcp.body.capability.name"
	attrBodyProtocolVersion = "mcp.body.protocol.version"
	attrBodyJSONRPCID       = "mcp.body.jsonrpc.id"
	attrBodyUnusable        = "mcp.body.unusable"
)

// specVersionModern is the first revision that mirrors values into headers. Versions are
// ISO-8601 dates, so lexical comparison is chronological and needs no date parsing.
//
// This classifies an era; it does not restrict one. The policy accepts every version — it
// only needs to know which of them put anything in the headers it validates.
const specVersionModern = "2026-07-28"

// Reasons the resolver publishes under attrBodyUnusable. It publishes one of these
// *instead of* the body facts, never alongside them, so a reason present means there is
// nothing to compare against and no point looking.
const (
	reasonSyntaxError       = "syntax-error"
	reasonInvalidMemberType = "invalid-member-type"
	reasonNotAnObject       = "not-an-object"
	reasonAmbiguous         = "ambiguous"
)

// methodsRequiringName are the operations whose target is named in Mcp-Name, and so the
// operations that must send it. Every other method addresses no particular capability, so
// the header is optional there.
var methodsRequiringName = map[string]bool{
	"tools/call":     true,
	"resources/read": true,
	"prompts/get":    true,
}

// McpValidationPolicy validates one route's MCP requests.
//
// It holds no state: the policy takes no parameters, and everything it needs arrives with
// the request. One instance is shared across all concurrent requests, which is safe
// precisely because there is nothing to share.
type McpValidationPolicy struct{}

// GetPolicy builds the policy for one route. There is nothing to configure and therefore
// nothing that can be misconfigured.
func GetPolicy(_ policy.PolicyMetadata, _ map[string]interface{}) (policy.Policy, error) {
	return &McpValidationPolicy{}, nil
}

// Mode asks for the request headers and nothing else.
//
// In particular it does NOT ask for the body, even though it validates body-derived facts.
// The route's resolver reads the body — that is the point of the whole mechanism — and
// asking for it again would make every route this policy is attached to buffer twice.
func (p *McpValidationPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders runs the validation. Returning nil forwards the request unchanged.
//
// Steps 0-2 apply to every MCP request; steps 4-7 only to one declaring a modern protocol
// version. The split matters: a legacy revision mirrors nothing into headers, so Mcp-Method
// and Mcp-Name are not part of its contract and this policy has no business adjudicating
// them.
func (p *McpValidationPolicy) OnRequestHeaders(
	_ context.Context,
	reqCtx *policy.RequestHeaderContext,
	_ map[string]interface{},
) policy.RequestHeaderAction {
	// Only the multiplexed POST endpoint carries a JSON-RPC body and mirrored headers. GET
	// and DELETE /mcp and the OAuth metadata route each mean exactly one thing.
	if !strings.EqualFold(reqCtx.Method, http.MethodPost) {
		return nil
	}

	reject := func(code int, message string) policy.RequestHeaderAction {
		slog.Debug("MCP Validation Policy: rejecting request", "code", code, "reason", message)
		return errorResponse(reqCtx.Headers, code, message, p.requestID(reqCtx), nil)
	}

	// ─── 0. Did the resolver run at all? ────────────────────────────────────
	//
	// Every fact below comes from the route's MCP resolver. Without it this policy can
	// validate nothing, and a validation policy that cannot validate must not report
	// success — silently forwarding would leave the route unprotected while appearing
	// healthy.
	//
	// ResolvedOperation, not the attributes, is the test. An empty attribute set proves
	// nothing about the resolver — a bodyless POST on a resolved route produces exactly
	// that, and is judged on its merits further down. Only a route with no protocol
	// resolver reports no operation at all.
	if reqCtx.ResolvedOperation == "" {
		slog.Error("MCP Validation Policy: no MCP resolver on this route; " +
			"the policy is attached to a route the gateway does not resolve as MCP")
		return reject(codeHeaderMismatch,
			"this route has no MCP operation resolver, so the request cannot be validated")
	}

	// ─── 1. Format of the version header, on the raw value ──────────────────
	//
	// Before anything reads it. The charset rule governs what actually travelled on the
	// wire, and this is the one header the policy acts on regardless of era — it decides
	// the branch below and is compared against the body further down.
	rawVersion := firstHeader(reqCtx.Headers, headerProtocolVersion)
	if rawVersion != "" && !isValidFieldValue(rawVersion) {
		return reject(codeHeaderMismatch,
			headerProtocolVersion+" contains characters not permitted in an HTTP field value")
	}

	// ─── 2. Could the body be read? ─────────────────────────────────────────
	//
	// Both eras. The resolver reports a reason only when it could not extract a JSON-RPC
	// envelope. A body that is merely empty, or that names no operation, was read
	// successfully and carries no reason — whatever else it did or did not publish. So a
	// reason here means the gateway and the backend may read these bytes differently, which
	// is the case no downstream policy can be allowed to govern.
	if reason := reqCtx.ResolutionAttributes.Get(attrBodyUnusable); reason != "" {
		code, message := unusableBodyError(reason)
		return reject(code, message)
	}

	// ─── 3. Which era is this request? ──────────────────────────────────────
	//
	// The era is the header's *value*, not its presence. 2025-06-18 defines
	// MCP-Protocol-Version too, so a conformant legacy client sends it — while mirroring
	// nothing into Mcp-Method or Mcp-Name, which arrived only in 2026-07-28. Treating any
	// version header as modern would reject every 2025-06-18 request for a missing
	// Mcp-Method, which is to say every request that works today.
	//
	// An absent header is older still: the spec lets a server read that as 2025-03-26.
	// Either way there is nothing mirrored to check, and the body has already been
	// validated above.
	if rawVersion == "" || rawVersion < specVersionModern {
		return nil
	}

	// ─── 4. Format of the mirrored headers ──────────────────────────────────
	//
	// Only now, because only a modern request defines them. They are checked whenever
	// present, required for this method or not: the spec scopes the *missing header*
	// failure to required headers, but not the invalid-characters one, and on a modern
	// request both are recognised standard headers.
	for _, name := range []string{headerMcpMethod, headerMcpName} {
		if raw := firstHeader(reqCtx.Headers, name); raw != "" && !isValidFieldValue(raw) {
			return reject(codeHeaderMismatch,
				name+" contains characters not permitted in an HTTP field value")
		}
	}

	// ─── 5. Presence ────────────────────────────────────────────────────────
	//
	// Which headers must be sent. Whether the ones that were sent tell the truth is step 7,
	// and the two are not the same question: Mcp-Name is optional on most methods, but a
	// value present on any of them is still compared.
	method := firstHeader(reqCtx.Headers, headerMcpMethod)
	if method == "" {
		return reject(codeHeaderMismatch, headerMcpMethod+" header is required")
	}
	name := firstHeader(reqCtx.Headers, headerMcpName)
	if methodsRequiringName[method] && name == "" {
		return reject(codeHeaderMismatch, headerMcpName+" header is required for "+method)
	}

	// ─── 6. Decode the sentinel ─────────────────────────────────────────────
	decodedName, err := decodeSentinel(name)
	if err != nil {
		return reject(codeHeaderMismatch, headerMcpName+" is not a valid base64 sentinel value")
	}

	// ─── 7. Is the body what the headers claim? ─────────────────────────────
	//
	// Three comparisons between a header and its counterpart in the body. The version and
	// the method are always present by now — step 3 established one, step 5 the other. The
	// name is compared whenever it was sent, which is not the same as whenever it was
	// required: a client that names a capability on a method that needs none is still
	// claiming something about the body, and the claim has to hold.
	//
	// A body value that is absent fails the same as one that differs: a modern client MUST
	// mirror, so the counterpart is required to exist. Only the message separates the two.
	//
	// Version is compared first, so a header declaring modern over a body that does not is
	// reported as that, rather than as whichever of method or name differs as a result.
	if bodyVersion := reqCtx.ResolutionAttributes.Get(attrBodyProtocolVersion); bodyVersion != rawVersion {
		return reject(codeHeaderMismatch,
			mirrorFailure(headerProtocolVersion, "protocol version", bodyVersion))
	}

	if bodyMethod := reqCtx.ResolutionAttributes.Get(attrBodyMethod); bodyMethod != method {
		return reject(codeHeaderMismatch, mirrorFailure(headerMcpMethod, "method", bodyMethod))
	}

	// On the raw header, not the decoded value: a degenerate "=?base64??=" decodes to "" and
	// would otherwise skip the comparison for a header the client did send.
	if name != "" {
		if bodyName := reqCtx.ResolutionAttributes.Get(attrBodyCapabilityName); bodyName != decodedName {
			return reject(codeHeaderMismatch, mirrorFailure(headerMcpName, "capability name", bodyName))
		}
	}

	// Mcp-Param-* is deliberately never validated. "Recognised" is defined by the tool's
	// own inputSchema, which the gateway never sees, so the spec requires an intermediary
	// to forward unrecognised ones and otherwise ignore them.
	return nil
}

// unusableBodyError maps a resolver reason onto the JSON-RPC error the client should see.
//
// The split follows the resolver's own classification, which in turn follows what the
// released MCP policies already returned: broken syntax is a parse error, everything else
// is an invalid request. Collapsing them would answer -32700 for a request whose JSON was
// fine and whose method was merely the wrong type.
func unusableBodyError(reason string) (int, string) {
	switch reason {
	case reasonSyntaxError:
		return codeParseError, "Request body is not valid JSON"
	case reasonInvalidMemberType:
		return codeInvalidRequest, "Request body has a member of the wrong type"
	case reasonNotAnObject:
		// A JSON-RPC batch names several operations and therefore identifies none, so the
		// gateway cannot say which one its policies would be governing.
		return codeInvalidRequest, "Request body is not a single JSON-RPC request object"
	case reasonAmbiguous:
		// The dangerous one: valid JSON that the backend may resolve differently than the
		// gateway did. Unlike the others it may not be rejected upstream at all.
		return codeInvalidRequest, "Request body names a member more than once"
	default:
		// An unrecognised reason means the resolver reports something this build does not
		// know about. It still means the body could not be read, so refuse rather than
		// forward a request no policy can safely govern.
		return codeInvalidRequest, "Request body could not be read"
	}
}

// requestID returns the JSON-RPC id to correlate an error with, or "" when the body was
// never read or carried none.
//
// A notification legitimately has no id, and the envelope then renders it as null. The
// spec permits exactly that: a notification the server cannot accept takes an HTTP error
// whose body "MAY comprise a JSON-RPC error response that has no id".
func (p *McpValidationPolicy) requestID(reqCtx *policy.RequestHeaderContext) string {
	return reqCtx.ResolutionAttributes.Get(attrBodyJSONRPCID)
}

// mirrorFailure renders the two ways a mirrored header can fail to be corroborated by the
// request body. Both are -32020, and the distinction is made in the message rather than in
// the outcome: "does not match" sends a reader looking for a value that differs, which is
// the wrong hunt when the body carried no such value at all.
func mirrorFailure(header, subject, bodyValue string) string {
	if bodyValue == "" {
		return header + " is set but the request body carries no " + subject
	}
	return header + " does not match the " + subject + " in the request body"
}

// firstHeader returns a header's first value, or "" when absent. Get is case-insensitive
// and returns a slice, since HTTP permits repeats.
func firstHeader(headers *policy.Headers, name string) string {
	values := headers.Get(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
