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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// JSON-RPC error codes this policy returns.
//
// The two base codes are JSON-RPC 2.0's own; -32020 is from the -32020..-32099 block MCP
// 2026-07-28 reserves for itself, so it must not be reused for anything else.
const (
	// codeParseError is a body whose JSON does not parse — in practice, truncation.
	codeParseError = -32700

	// codeInvalidRequest is a body that parses but is not a usable JSON-RPC request: a
	// batch, a bare scalar, a member of the wrong type, or a member named twice.
	codeInvalidRequest = -32600

	// codeHeaderMismatch covers every way the mirrored headers can fail: a required one
	// missing, a value outside the permitted charset, a malformed sentinel, or a value
	// that disagrees with the body.
	codeHeaderMismatch = -32020
)

// errorResponse renders a JSON-RPC error as the immediate response to a rejected request.
//
// The envelope matches what the other MCP policies emit (mcp-acl-list, mcp-ratelimit,
// mcp-rewrite each carry their own copy) so a client sees one error shape from the gateway
// regardless of which policy rejected it. The duplication is structural: policies are
// separate Go modules with no shared package.
//
// data is attached to the error object only when non-nil. No error this policy currently
// returns carries any, but the parameter stays because the spec defines data for several
// codes and adding one should not mean changing every call site.
func errorResponse(
	headers *policy.Headers,
	jsonRPCCode int,
	message string,
	requestID string,
	data map[string]any,
) policy.RequestHeaderAction {
	errObj := map[string]any{
		"code":    jsonRPCCode,
		"message": message,
	}
	if data != nil {
		errObj["data"] = data
	}

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      jsonRPCID(requestID),
		"error":   errObj,
	})
	if err != nil {
		// Unreachable for these types, but a marshalling failure must still produce a
		// well-formed JSON-RPC error rather than an empty body.
		slog.Debug("MCP Validation Policy: failed to marshal error response", "error", err)
		body = fmt.Appendf(nil,
			`{"jsonrpc":"2.0","id":null,"error":{"code":%d,"message":"Unexpected error"}}`,
			jsonRPCCode)
	}

	contentType := "application/json"
	if clientAcceptsEventStream(headers) {
		// A client that asked for a stream is reading SSE frames, not a JSON document.
		// Sending bare JSON would leave it waiting for a frame that never arrives.
		body = []byte("event: message\ndata: " + string(body) + "\n\n")
		contentType = "text/event-stream"
	}

	return policy.ImmediateResponse{
		StatusCode: http.StatusBadRequest,
		Headers:    map[string]string{"Content-Type": contentType},
		Body:       body,
		// Surfaces the rejection in analytics under the same key the other MCP policies
		// use, so validation failures are countable alongside authz and ACL rejections.
		AnalyticsMetadata: map[string]any{"mcpErrorCode": jsonRPCCode},
	}
}

// jsonRPCID renders the id for the error envelope.
//
// The resolver publishes it as the JSON token it arrived as — 7 for a number, "7" with its
// quotes for a string — so it is echoed back verbatim rather than re-parsed. Re-parsing is
// what used to answer `"id":"7"` with `"id":7`, which a client matching on the value cannot
// correlate. An id we never saw becomes null, which the spec permits for an uncorrelatable
// error. The validity check is defensive: a mangled attribute must not produce a malformed body.
func jsonRPCID(raw string) any {
	if !json.Valid([]byte(raw)) {
		return nil
	}
	return json.RawMessage(raw)
}

// clientAcceptsEventStream reports whether the caller asked for an SSE response.
func clientAcceptsEventStream(headers *policy.Headers) bool {
	if headers == nil {
		return false
	}
	for _, value := range headers.Get("accept") {
		if strings.Contains(strings.ToLower(value), "text/event-stream") {
			return true
		}
	}
	return false
}
