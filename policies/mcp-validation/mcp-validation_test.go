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
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	legacyVersion = "2025-06-18"
	modernVersion = "2026-07-28"

	// mcpOperation is what the engine's MCP resolver reports for a resolved route. Its
	// presence is how the policy knows a resolver ran at all.
	mcpOperation = "mcp"
)

func newPolicy(t *testing.T) *McpValidationPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*McpValidationPolicy)
}

// newRequest builds a POST on a route the MCP resolver ran on, which is every request the
// policy is meant to see.
func newRequest(headers map[string]string, attrs map[string]string) *policy.RequestHeaderContext {
	reqCtx := newUnresolvedRequest(headers, attrs)
	reqCtx.ResolvedOperation = mcpOperation
	return reqCtx
}

// newUnresolvedRequest builds a POST on a route with no protocol resolver — the policy
// attached to a non-MCP API, or running on an engine with no MCP resolver at all.
func newUnresolvedRequest(headers map[string]string, attrs map[string]string) *policy.RequestHeaderContext {
	hdrs := make(map[string][]string, len(headers))
	for k, v := range headers {
		hdrs[k] = []string{v}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			ResolutionAttributes: policy.NewResolutionAttributes(attrs),
		},
		Headers: policy.NewHeaders(hdrs),
		Method:  "POST",
	}
}

// modernAttrs is what the resolver publishes for a well-formed modern tools/call.
func modernAttrs(extra map[string]string) map[string]string {
	attrs := map[string]string{attrBodyProtocolVersion: modernVersion}
	for k, v := range extra {
		attrs[k] = v
	}
	return attrs
}

// rejection unpacks an ImmediateResponse into its JSON-RPC error code and object. It fails
// the test if the action forwarded the request instead.
func rejection(t *testing.T, action policy.RequestHeaderAction) (int, map[string]any) {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected the request to be rejected, got %T", action)
	}
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	body := resp.Body
	if strings.HasPrefix(string(body), "event:") {
		_, after, _ := strings.Cut(string(body), "data: ")
		body = []byte(strings.TrimSpace(after))
	}
	var envelope struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, body)
	}
	code, _ := envelope.Error["code"].(float64)
	return int(code), envelope.Error
}

func assertForwarded(t *testing.T, action policy.RequestHeaderAction) {
	t.Helper()
	if action != nil {
		t.Fatalf("expected the request to be forwarded, got %#v", action)
	}
}

func run(t *testing.T, p *McpValidationPolicy, reqCtx *policy.RequestHeaderContext) policy.RequestHeaderAction {
	t.Helper()
	return p.OnRequestHeaders(context.Background(), reqCtx, nil)
}

// ─── The resolver must have run ──────────────────────────────────────────────

// Without a resolver the policy has no facts and can validate nothing. Reporting success
// would leave the route unprotected while the policy appears attached and healthy.
func TestRouteWithoutAResolverIsRejected(t *testing.T) {
	p := newPolicy(t)
	code, errObj := rejection(t, run(t, p, newUnresolvedRequest(
		map[string]string{headerProtocolVersion: modernVersion, headerMcpMethod: "tools/list"},
		nil,
	)))

	if code != codeHeaderMismatch {
		t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
	}
	if message, _ := errObj["message"].(string); !strings.Contains(message, "resolver") {
		t.Errorf("message = %q, want it to name the missing resolver", message)
	}
}

// The counterpart, and the distinction that matters. Both a route with no resolver and a
// resolved route whose body carried nothing are rejected — but for different reasons, and
// an operator has to be able to tell which they are looking at. One is a deployment fault
// they must fix; the other is a request the caller sent wrong.
func TestNoResolverIsReportedDifferentlyFromAnEmptyBody(t *testing.T) {
	p := newPolicy(t)
	headers := map[string]string{
		headerProtocolVersion: modernVersion,
		headerMcpMethod:       "tools/call",
		headerMcpName:         "get_forecast",
	}

	t.Run("no resolver on the route names the resolver", func(t *testing.T) {
		_, errObj := rejection(t, run(t, p, newUnresolvedRequest(headers, nil)))
		if message, _ := errObj["message"].(string); !strings.Contains(message, "resolver") {
			t.Errorf("message = %q, want it to name the missing resolver", message)
		}
	})

	t.Run("a resolved route with an empty body names the header the body did not mirror",
		func(t *testing.T) {
			_, errObj := rejection(t, run(t, p, newRequest(headers, nil)))
			message, _ := errObj["message"].(string)
			if strings.Contains(message, "resolver") {
				t.Errorf("message = %q, must not blame the resolver: it ran fine", message)
			}
			if !strings.Contains(message, headerProtocolVersion) {
				t.Errorf("message = %q, want it to name the version header", message)
			}
		})
}

// ─── Era dispatch ────────────────────────────────────────────────────────────

// The era is the header's value, not its presence. 2025-06-18 defines
// MCP-Protocol-Version but mirrors nothing into Mcp-Method or Mcp-Name, so treating any
// version header as modern would reject every conformant legacy request.
func TestEraIsDecidedByVersionValueNotHeaderPresence(t *testing.T) {
	p := newPolicy(t)

	t.Run("no version header is pre-2025-06-18 and forwards", func(t *testing.T) {
		assertForwarded(t, run(t, p, newRequest(nil, nil)))
	})

	t.Run("a legacy version forwards despite a body method and no Mcp-Method", func(t *testing.T) {
		assertForwarded(t, run(t, p, newRequest(
			map[string]string{headerProtocolVersion: legacyVersion},
			map[string]string{attrBodyMethod: "tools/call"},
		)))
	})

	t.Run("a modern version applies the header checks", func(t *testing.T) {
		code, _ := rejection(t, run(t, p, newRequest(
			map[string]string{headerProtocolVersion: modernVersion}, // Mcp-Method missing
			nil,
		)))
		if code != codeHeaderMismatch {
			t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
		}
	})
}

// ─── Body validation, both eras ──────────────────────────────────────────────

// The resolver reports why it could not read a body; the policy turns that into the error
// the client should see. Broken syntax is a parse error, everything else an invalid
// request — collapsing them would answer -32700 for a document that parsed fine.
func TestUnreadableBodyIsRejectedWithTheMappedCode(t *testing.T) {
	p := newPolicy(t)

	tests := []struct {
		reason string
		want   int
	}{
		{reasonSyntaxError, codeParseError},
		{reasonInvalidMemberType, codeInvalidRequest},
		{reasonNotAnObject, codeInvalidRequest},
		{reasonAmbiguous, codeInvalidRequest},
		// A reason this build does not recognise still means the body was unreadable.
		{"something-new", codeInvalidRequest},
	}

	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			code, _ := rejection(t, run(t, p, newRequest(
				map[string]string{headerProtocolVersion: modernVersion},
				map[string]string{attrBodyUnusable: tc.reason},
			)))
			if code != tc.want {
				t.Errorf("code = %d, want %d", code, tc.want)
			}
		})
	}
}

// Body validation is era-independent. A legacy request skips every header check, but an
// unreadable body is still a fault the gateway must not pass on — this is the case the
// previous design silently forwarded.
func TestUnreadableBodyIsRejectedOnALegacyRequestToo(t *testing.T) {
	p := newPolicy(t)
	code, _ := rejection(t, run(t, p, newRequest(
		map[string]string{headerProtocolVersion: legacyVersion},
		map[string]string{attrBodyUnusable: reasonAmbiguous},
	)))
	if code != codeInvalidRequest {
		t.Errorf("code = %d, want %d", code, codeInvalidRequest)
	}
}

// ─── The modern header checks ────────────────────────────────────────────────

func TestModernChecks(t *testing.T) {
	p := newPolicy(t)

	tests := []struct {
		name    string
		headers map[string]string
		attrs   map[string]string
		reject  bool
	}{
		{
			name: "agreeing headers and body are forwarded",
			headers: map[string]string{
				headerProtocolVersion: modernVersion,
				headerMcpMethod:       "tools/call",
				headerMcpName:         "get_forecast",
			},
			attrs: modernAttrs(map[string]string{
				attrBodyMethod: "tools/call", attrBodyCapabilityName: "get_forecast",
			}),
		},
		{
			name:    "Mcp-Method missing",
			headers: map[string]string{headerProtocolVersion: modernVersion},
			reject:  true,
		},
		{
			name: "Mcp-Name missing for tools/call",
			headers: map[string]string{
				headerProtocolVersion: modernVersion, headerMcpMethod: "tools/call",
			},
			reject: true,
		},
		{
			name: "Mcp-Name not required for tools/list",
			headers: map[string]string{
				headerProtocolVersion: modernVersion, headerMcpMethod: "tools/list",
			},
			attrs: modernAttrs(map[string]string{attrBodyMethod: "tools/list"}),
		},
		{
			name: "the declared version disagrees with the body",
			headers: map[string]string{
				headerProtocolVersion: modernVersion, headerMcpMethod: "tools/list",
			},
			attrs: map[string]string{
				attrBodyMethod: "tools/list", attrBodyProtocolVersion: legacyVersion,
			},
			reject: true,
		},
		{
			name: "method disagrees with the body",
			headers: map[string]string{
				headerProtocolVersion: modernVersion, headerMcpMethod: "tools/list",
			},
			attrs:  modernAttrs(map[string]string{attrBodyMethod: "tools/call"}),
			reject: true,
		},
		{
			name: "capability name disagrees with the body",
			headers: map[string]string{
				headerProtocolVersion: modernVersion,
				headerMcpMethod:       "tools/call",
				headerMcpName:         "get_forecast",
			},
			attrs: modernAttrs(map[string]string{
				attrBodyMethod: "tools/call", attrBodyCapabilityName: "delete_everything",
			}),
			reject: true,
		},
		{
			name: "a sentinel-encoded name is decoded before comparing",
			headers: map[string]string{
				headerProtocolVersion: modernVersion,
				headerMcpMethod:       "tools/call",
				headerMcpName:         "=?base64?Z2V0X2ZvcmVjYXN0?=",
			},
			attrs: modernAttrs(map[string]string{
				attrBodyMethod: "tools/call", attrBodyCapabilityName: "get_forecast",
			}),
		},
		{
			name: "a malformed sentinel is rejected",
			headers: map[string]string{
				headerProtocolVersion: modernVersion,
				headerMcpMethod:       "tools/call",
				headerMcpName:         "=?base64?not!base64?=",
			},
			attrs:  modernAttrs(map[string]string{attrBodyMethod: "tools/call"}),
			reject: true,
		},
		{
			name: "a header carrying CRLF is rejected",
			headers: map[string]string{
				headerProtocolVersion: modernVersion,
				headerMcpMethod:       "tools/call\r\nX-Injected: 1",
			},
			reject: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			action := run(t, p, newRequest(tc.headers, tc.attrs))
			if !tc.reject {
				assertForwarded(t, action)
				return
			}
			if code, _ := rejection(t, action); code != codeHeaderMismatch {
				t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
			}
		})
	}
}

// Check order is load-bearing: the charset rule applies to what travelled on the wire, so
// a value that is both malformed and mismatched must report the format failure. If decode
// ran first, a payload could smuggle forbidden octets through the sentinel unexamined.
func TestFormatCheckPrecedesComparison(t *testing.T) {
	p := newPolicy(t)
	action := run(t, p, newRequest(
		map[string]string{
			headerProtocolVersion: modernVersion,
			headerMcpMethod:       "tools/call\n", // charset violation
		},
		modernAttrs(map[string]string{attrBodyMethod: "tools/list"}), // and a mismatch
	))

	_, errObj := rejection(t, action)
	message, _ := errObj["message"].(string)
	if !strings.Contains(message, "not permitted") {
		t.Errorf("message = %q, want the format failure to be reported first", message)
	}
}

// ─── The body must corroborate the headers ───────────────────────────────────

// On a modern request the client MUST mirror, so each header compared at step 7 has a body
// counterpart that is required to exist. A body carrying none fails exactly as a differing
// value does, and all three headers behave the same way.
//
// The cases are enumerated rather than sampled because the absent and differing forms take
// separate paths through the message, and because a guard added to any one of the three
// would silently make it forward where the other two reject.
func TestAbsentBodyValuesFailLikeDifferingOnes(t *testing.T) {
	p := newPolicy(t)
	headers := map[string]string{
		headerProtocolVersion: modernVersion,
		headerMcpMethod:       "tools/call",
		headerMcpName:         "get_forecast",
	}
	full := map[string]string{
		attrBodyProtocolVersion: modernVersion,
		attrBodyMethod:          "tools/call",
		attrBodyCapabilityName:  "get_forecast",
	}

	// The control: everything mirrored, so the request goes through.
	t.Run("a fully mirrored body forwards", func(t *testing.T) {
		assertForwarded(t, run(t, p, newRequest(headers, full)))
	})

	without := func(key string) map[string]string {
		attrs := map[string]string{}
		for k, v := range full {
			if k != key {
				attrs[k] = v
			}
		}
		return attrs
	}

	cases := []struct {
		name   string
		attrs  map[string]string
		wantIn string
		absent bool
	}{
		{"no protocol version in the body", without(attrBodyProtocolVersion), headerProtocolVersion, true},
		{"no method in the body", without(attrBodyMethod), headerMcpMethod, true},
		{"no capability name in the body", without(attrBodyCapabilityName), headerMcpName, true},
		{"a differing protocol version", map[string]string{
			attrBodyProtocolVersion: legacyVersion, attrBodyMethod: "tools/call",
			attrBodyCapabilityName: "get_forecast"}, headerProtocolVersion, false},
		{"a differing method", map[string]string{
			attrBodyProtocolVersion: modernVersion, attrBodyMethod: "tools/list",
			attrBodyCapabilityName: "get_forecast"}, headerMcpMethod, false},
		{"a differing capability name", map[string]string{
			attrBodyProtocolVersion: modernVersion, attrBodyMethod: "tools/call",
			attrBodyCapabilityName: "delete_everything"}, headerMcpName, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, errObj := rejection(t, run(t, p, newRequest(headers, tc.attrs)))
			if code != codeHeaderMismatch {
				t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
			}
			message, _ := errObj["message"].(string)
			if !strings.Contains(message, tc.wantIn) {
				t.Errorf("message = %q, want it to name %s", message, tc.wantIn)
			}
			// Same outcome, different diagnosis: "does not match" would send the reader
			// hunting for a value that differs when there is no value at all.
			if got := strings.Contains(message, "carries no"); got != tc.absent {
				t.Errorf("message = %q, absent-case wording = %v, want %v", message, got, tc.absent)
			}
		})
	}
}

// Required and compared are two different questions. methodsRequiringName answers the
// first — must the client send Mcp-Name at all — and only tools/call, resources/read and
// prompts/get say yes. The second applies to every method: a value that was sent is a claim
// about the body, so it has to hold whether or not the method obliged the client to make it.
func TestMcpNameIsComparedWheneverItIsSent(t *testing.T) {
	p := newPolicy(t)

	headers := func(method, name string) map[string]string {
		h := map[string]string{headerProtocolVersion: modernVersion, headerMcpMethod: method}
		if name != "" {
			h[headerMcpName] = name
		}
		return h
	}
	body := func(method, name string) map[string]string {
		attrs := map[string]string{attrBodyProtocolVersion: modernVersion, attrBodyMethod: method}
		if name != "" {
			attrs[attrBodyCapabilityName] = name
		}
		return attrs
	}

	cases := []struct {
		name       string
		method     string
		headerName string
		bodyName   string
		reject     bool
	}{
		{"not sent, nothing in the body either", "tools/list", "", "", false},
		{
			// The body saying more than the header is not a failure to mirror: the spec
			// asks the client to mirror only for the three methods that require the header.
			name: "not sent, though the body names something", method: "tools/list",
			headerName: "", bodyName: "get_forecast", reject: false,
		},
		{
			// The gap this test exists for. Downstream policies read Mcp-Name; before the
			// fix nothing checked it here on a method that did not require it.
			name: "sent on a method that names no capability", method: "tools/list",
			headerName: "delete_everything", bodyName: "", reject: true,
		},
		{"sent and agreeing", "tools/list", "get_forecast", "get_forecast", false},

		// resources/subscribe is the realistic non-required case: it carries params.uri,
		// which the resolver publishes under the same capability.name key.
		{
			name: "an optional header agreeing with params.uri", method: "resources/subscribe",
			headerName: "file:///a.txt", bodyName: "file:///a.txt", reject: false,
		},
		{
			name: "an optional header disagreeing with params.uri", method: "resources/subscribe",
			headerName: "file:///a.txt", bodyName: "file:///secrets.txt", reject: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action := run(t, p, newRequest(
				headers(tc.method, tc.headerName), body(tc.method, tc.bodyName)))
			if !tc.reject {
				assertForwarded(t, action)
				return
			}
			code, errObj := rejection(t, action)
			if code != codeHeaderMismatch {
				t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
			}
			if message, _ := errObj["message"].(string); !strings.Contains(message, headerMcpName) {
				t.Errorf("message = %q, want it to name %s", message, headerMcpName)
			}
		})
	}
}

// The comparison is gated on the raw header, not the decoded value. "=?base64??=" is a
// well-formed sentinel carrying an empty payload, so it decodes without error to "" —
// gating on the decoded value would read that as "no header sent" and skip the comparison
// on a tools/call, where step 5 only guarantees the raw value is non-empty.
func TestAnEmptySentinelIsStillAHeaderThatWasSent(t *testing.T) {
	p := newPolicy(t)
	code, _ := rejection(t, run(t, p, newRequest(
		map[string]string{
			headerProtocolVersion: modernVersion,
			headerMcpMethod:       "tools/call",
			headerMcpName:         "=?base64??=",
		},
		map[string]string{
			attrBodyProtocolVersion: modernVersion,
			attrBodyMethod:          "tools/call",
			attrBodyCapabilityName:  "get_forecast",
		},
	)))
	if code != codeHeaderMismatch {
		t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
	}
}

// ─── Which headers belong to which revision ──────────────────────────────────

// The charset rule follows the revision, not the request. Mcp-Name is not part of
// 2025-06-18, so a legacy request carrying a malformed one is forwarded — the gateway does
// not adjudicate a header that revision never defined, and rejecting would newly break a
// client that works today. The same header on a modern request is rejected.
func TestMirroredHeaderCharsetIsCheckedOnlyOnModernRequests(t *testing.T) {
	p := newPolicy(t)
	malformed := map[string]string{headerMcpName: "get\nforecast"}

	t.Run("legacy request forwards", func(t *testing.T) {
		headers := map[string]string{headerProtocolVersion: legacyVersion}
		headers[headerMcpName] = malformed[headerMcpName]
		assertForwarded(t, run(t, p, newRequest(headers, nil)))
	})

	t.Run("modern request rejects", func(t *testing.T) {
		headers := map[string]string{
			headerProtocolVersion: modernVersion,
			headerMcpMethod:       "tools/call",
		}
		headers[headerMcpName] = malformed[headerMcpName]
		code, _ := rejection(t, run(t, p, newRequest(headers, nil)))
		if code != codeHeaderMismatch {
			t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
		}
	})
}

// Recognised, therefore validated — even where not required. The spec scopes only the
// missing-header failure to required headers; "a header value contains invalid characters"
// is unqualified, and Mcp-Name is a standard header of this revision whatever the method.
func TestMalformedMcpNameIsRejectedEvenWhereNotRequired(t *testing.T) {
	p := newPolicy(t)
	code, _ := rejection(t, run(t, p, newRequest(
		map[string]string{
			headerProtocolVersion: modernVersion,
			headerMcpMethod:       "tools/list", // does not require Mcp-Name
			headerMcpName:         "stray\nvalue",
		},
		modernAttrs(map[string]string{attrBodyMethod: "tools/list"}),
	)))
	if code != codeHeaderMismatch {
		t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
	}
}

// ─── Scope ───────────────────────────────────────────────────────────────────

// Only the multiplexed POST endpoint carries a JSON-RPC body and mirrored headers.
// GET/DELETE /mcp and the OAuth metadata route each mean one thing and have nothing to
// validate — not even the resolver check, which would otherwise reject them all.
func TestNonPostRequestsAreNotValidated(t *testing.T) {
	p := newPolicy(t)
	reqCtx := newUnresolvedRequest(nil, nil)
	reqCtx.Method = "GET"
	assertForwarded(t, run(t, p, reqCtx))
}

func TestModeAsksForHeadersOnly(t *testing.T) {
	mode := newPolicy(t).Mode()
	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Error("the policy must run at the request-header phase")
	}
	// The body is read by the resolver. If this policy ever asks for it, every route it is
	// attached to buffers twice over.
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Error("the policy must not ask for the request body")
	}
}

// ─── Configuration ───────────────────────────────────────────────────────────

// The policy takes no parameters, so there is nothing to misconfigure. This is the exact
// breakage the rework fixes: the previous version required a controller-injected list and
// failed the whole chain build without it.
func TestGetPolicyNeedsNoParameters(t *testing.T) {
	for _, params := range []map[string]interface{}{
		nil,
		{},
		{"supportedVersions": []interface{}{"2026-07-28"}}, // a stale value is simply ignored
	} {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err != nil {
			t.Errorf("GetPolicy(%v) = %v, want no error", params, err)
		}
	}
}

// ─── Error rendering ─────────────────────────────────────────────────────────

func TestErrorEnvelopeCorrelatesWithTheRequest(t *testing.T) {
	p := newPolicy(t)
	resp := run(t, p, newRequest(
		map[string]string{headerProtocolVersion: modernVersion},
		map[string]string{attrBodyJSONRPCID: "7"},
	)).(policy.ImmediateResponse)

	var envelope map[string]any
	if err := json.Unmarshal(resp.Body, &envelope); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	// A numeric id must round-trip as a number, not as the string "7".
	if id, _ := envelope["id"].(float64); id != 7 {
		t.Errorf("id = %v, want the numeric id 7", envelope["id"])
	}
	if resp.AnalyticsMetadata["mcpErrorCode"] != codeHeaderMismatch {
		t.Errorf("the rejection must be countable in analytics, got %v", resp.AnalyticsMetadata)
	}
}

// The id round-trips as the JSON type the client sent, because that is what a client matches
// its pending request against. The resolver publishes the token it arrived as, and this policy
// echoes it verbatim — re-parsing it is what used to answer `"id":"7"` with `"id":7`, which no
// client would correlate.
func TestErrorIDRoundTripsItsJSONType(t *testing.T) {
	cases := []struct {
		name      string
		attribute string // as the resolver publishes it
		want      string // as it must appear in the envelope
	}{
		{"a number stays a number", `7`, `"id":7`},
		{"a numeric string stays a string", `"7"`, `"id":"7"`},
		{"a non-numeric string", `"req-7"`, `"id":"req-7"`},
		{"an empty string is an id, not an absence", `""`, `"id":""`},
		{"zero", `0`, `"id":0`},
		// Defensive only: the resolver cannot produce this, but a mangled attribute must not
		// yield a malformed response body.
		{"a value that is not JSON falls back to null", `not-json`, `"id":null`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPolicy(t)
			resp := run(t, p, newRequest(
				map[string]string{headerProtocolVersion: modernVersion},
				map[string]string{attrBodyJSONRPCID: tc.attribute},
			)).(policy.ImmediateResponse)

			if !strings.Contains(string(resp.Body), tc.want) {
				t.Errorf("body = %s, want it to contain %s", resp.Body, tc.want)
			}
			// Whatever the id, the envelope must stay valid JSON.
			var envelope map[string]any
			if err := json.Unmarshal(resp.Body, &envelope); err != nil {
				t.Fatalf("body is not valid JSON: %v", err)
			}
		})
	}
}

// A notification carries no id, so the resolver publishes none, and the spec permits an
// error response that has none. The envelope must render that as an explicit null rather
// than omitting the member or inventing an id — which is why the policy needs no special
// case for notifications at all.
func TestErrorWithoutARequestIDCarriesAnExplicitNull(t *testing.T) {
	p := newPolicy(t)
	resp := run(t, p, newRequest(
		map[string]string{headerProtocolVersion: modernVersion}, // Mcp-Method missing
		nil, // a notification publishes no mcp.body.jsonrpc.id
	)).(policy.ImmediateResponse)

	var envelope map[string]any
	if err := json.Unmarshal(resp.Body, &envelope); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if id, present := envelope["id"]; !present || id != nil {
		t.Errorf("id = %v (present=%v), want an explicit null", id, present)
	}
}

func TestErrorIsSseFramedWhenTheClientAsksForAStream(t *testing.T) {
	p := newPolicy(t)
	resp := run(t, p, newRequest(
		map[string]string{headerProtocolVersion: modernVersion, "Accept": "text/event-stream"},
		nil,
	)).(policy.ImmediateResponse)

	if got := resp.Headers["Content-Type"]; got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}
	if !strings.HasPrefix(string(resp.Body), "event: message\ndata: ") {
		t.Errorf("body is not an SSE frame: %q", resp.Body)
	}
}
