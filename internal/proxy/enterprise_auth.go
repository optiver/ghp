package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/goodtune/ghp/internal/metrics"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// Login only needs a tiny query. Bound inspection of otherwise transparent
// passthrough traffic independently of the proxy-token scope analyzer.
const maxEnterpriseLoginBodyBytes = 4096

// ApplyAPI also permits the identity and scope checks needed to log in with
// an external account when at least one valid repository exception exists.
// This does not grant access to repositories or substitute a managed identity.
func (p *EnterprisePolicy) ApplyAPI(r *http.Request, username UsernameFunc, tokenType string) string {
	if p == nil {
		return ""
	}
	start := time.Now()
	defer func() {
		metrics.ObserveDecision(metrics.StageEnterpriseException, tokenType, time.Since(start))
	}()
	if len(p.exceptions) > 0 && isEnterpriseLoginRequest(r) {
		r.Header.Del(enterpriseHeader)
		metrics.EnterpriseExceptionTotal.WithLabelValues("auth_header_omitted").Inc()
		return ""
	}
	owner, repo := enterpriseTargetFromAPIPath(r.URL.Path)
	return p.apply(r.Context(), r.Header, owner, repo, username)
}

func isEnterpriseLoginRequest(r *http.Request) bool {
	_, credential, _ := extractClientToken(r)
	if credential == "" || r.URL.RawQuery != "" {
		return false
	}
	// gh checks X-OAuth-Scopes on the API root when validating a supplied
	// token. Only this exact read endpoint is exempt, not /user or its children.
	if r.Method == http.MethodGet && r.URL.Path == "/" && (r.Body == nil || r.Body == http.NoBody) {
		return true
	}
	if r.Method != http.MethodPost || r.URL.Path != "/graphql" || r.Body == nil || r.Header.Get("Content-Encoding") != "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return false
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxEnterpriseLoginBodyBytes+1))
	// Replay every inspected byte, including on oversized/malformed requests.
	// Keep the original Close method so upstream forwarding releases the body.
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(body), r.Body), r.Body}
	if err != nil || len(body) > maxEnterpriseLoginBodyBytes {
		return false
	}
	return isEnterpriseLoginQuery(body)
}

func isEnterpriseLoginQuery(body []byte) bool {
	// Require one unambiguous JSON envelope. In particular, duplicate keys,
	// case variants, URL parameters and persisted-query extensions must not let
	// GitHub execute a different query than the one inspected here.
	dec := json.NewDecoder(bytes.NewReader(body))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	var request graphQLRequestBody
	seen := make(map[string]bool)
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return false
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return false
		}
		seen[name] = true
		switch name {
		case "query":
			err = dec.Decode(&request.Query)
		case "operationName":
			err = dec.Decode(&request.OperationName)
		case "variables":
			err = dec.Decode(&request.Variables)
		default:
			return false
		}
		if err != nil {
			return false
		}
	}
	if last, err := dec.Token(); err != nil || last != json.Delim('}') {
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		return false
	}

	doc, err := parser.ParseQuery(&ast.Source{Input: request.Query})
	if err != nil || len(doc.Operations) != 1 || len(doc.Fragments) != 0 {
		return false
	}
	op := doc.Operations[0]
	if op.Operation != ast.Query || len(op.VariableDefinitions) != 0 || len(op.Directives) != 0 || len(op.SelectionSet) != 1 {
		return false
	}
	if request.OperationName != "" && request.OperationName != op.Name {
		return false
	}
	viewer, ok := op.SelectionSet[0].(*ast.Field)
	if !ok || viewer.Name != "viewer" || len(viewer.Arguments) != 0 || len(viewer.Directives) != 0 || len(viewer.SelectionSet) != 1 {
		return false
	}
	login, ok := viewer.SelectionSet[0].(*ast.Field)
	return ok && login.Name == "login" && len(login.Arguments) == 0 && len(login.Directives) == 0 && len(login.SelectionSet) == 0
}
