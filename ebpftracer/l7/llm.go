package l7

import (
	"bytes"
	"strings"
)

type LLMRequest struct {
	Operation string
	Model     string
}

const (
	LLMOperationChat           = "chat"
	LLMOperationTextCompletion = "text_completion"
	LLMOperationInference      = "inference"
)

var llmPaths = []struct {
	suffix string
	op     string
	weak   bool
}{
	{"/v1/chat/completions", LLMOperationChat, false},
	{"/v1/completions", LLMOperationTextCompletion, false},
	{"/generate_stream", LLMOperationTextCompletion, false}, // TGI
	{"/v1/messages", LLMOperationChat, true},                // Anthropic
	{"/v1/responses", LLMOperationChat, true},               // OpenAI Responses API
	{"/api/chat", LLMOperationChat, true},                   // Ollama
	{"/api/generate", LLMOperationTextCompletion, true},     // Ollama
	{"/generate", LLMOperationTextCompletion, true},         // TGI
}

func ParseLLMRequest(method, path string, payload []byte) *LLMRequest {
	if method != "POST" || path == "" {
		return nil
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	op, weak := llmOperation(path)
	if op == "" {
		return nil
	}
	body := httpBody(payload)
	if weak && !looksLikeLLMBody(body) {
		return nil
	}
	return &LLMRequest{Operation: op, Model: llmModel(body)}
}

func llmOperation(path string) (op string, weak bool) {
	switch {
	case path == "/inference.GRPCInferenceService/ModelInfer": // KServe v2 / Triton gRPC
		return LLMOperationInference, false
	case strings.HasSuffix(path, ":predict"): // KServe v1: /v1/models/<name>:predict
		return LLMOperationInference, false
	case strings.HasPrefix(path, "/v2/models/"): // KServe v2 / Triton: /v2/models/<name>[/versions/<v>]/{infer,generate,generate_stream}
		switch {
		case strings.HasSuffix(path, "/infer"):
			return LLMOperationInference, false
		case strings.HasSuffix(path, "/generate"), strings.HasSuffix(path, "/generate_stream"):
			return LLMOperationTextCompletion, false
		}
		return "", false
	}
	for _, p := range llmPaths {
		if strings.HasSuffix(path, p.suffix) {
			return p.op, p.weak
		}
	}
	return "", false
}

func httpBody(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	_, body, ok := bytes.Cut(payload, []byte("\r\n\r\n"))
	if !ok {
		return nil
	}
	return body
}

func looksLikeLLMBody(body []byte) bool {
	if !bytes.Contains(body, []byte(`"model"`)) {
		return false
	}
	for _, f := range []string{`"messages"`, `"prompt"`, `"max_tokens"`, `"input"`} {
		if bytes.Contains(body, []byte(f)) {
			return true
		}
	}
	return false
}

func llmModel(body []byte) string {
	_, rest, ok := bytes.Cut(body, []byte(`"model"`))
	if !ok {
		return ""
	}
	rest = bytes.TrimLeft(rest, " \t\r\n")
	if len(rest) == 0 || rest[0] != ':' {
		return ""
	}
	rest = bytes.TrimLeft(rest[1:], " \t\r\n")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	model, _, ok := bytes.Cut(rest[1:], []byte{'"'})
	if !ok { // truncated
		return ""
	}
	return string(model)
}
