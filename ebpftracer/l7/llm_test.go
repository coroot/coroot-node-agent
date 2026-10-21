package l7

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLLMRequest(t *testing.T) {
	chatBody := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"model\": \"qwen\", \"messages\": [{\"role\": \"user\", \"content\": \"hi\"}]}"
	anthropicBody := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nanthropic-version: 2023-06-01\r\n\r\n{\"model\":\"claude-sonnet-4-5\",\"max_tokens\":1024,\"messages\":[]}"
	truncated := "POST /v1/chat/completions HTTP/1.1\r\nHost: h\r\n\r\n{\"model\":\"qwe"
	headersOnly := "POST /v1/messages HTTP/1.1\r\nHost: h\r\n\r\n"

	for _, c := range []struct {
		method, path string
		payload      string
		want         *LLMRequest
	}{
		{"POST", "/v1/chat/completions", chatBody, &LLMRequest{Operation: "chat", Model: "qwen"}},
		{"POST", "/v1/chat/completions?api-version=2024-02-01", chatBody, &LLMRequest{Operation: "chat", Model: "qwen"}},
		{"POST", "/openai/deployments/gpt-4o/chat/completions", "", nil}, // no "/v1/chat/completions" suffix: not matched on purpose
		{"POST", "/openai/v1/chat/completions", "", &LLMRequest{Operation: "chat"}},
		{"POST", "/v1/completions", "", &LLMRequest{Operation: "text_completion"}},
		{"POST", "/v1/chat/completions", truncated, &LLMRequest{Operation: "chat"}},
		{"GET", "/v1/chat/completions", "", nil},
		{"POST", "/v1/embeddings", chatBody, nil},
		{"POST", "/v1/messages", anthropicBody, &LLMRequest{Operation: "chat", Model: "claude-sonnet-4-5"}},
		{"POST", "/v1/messages", headersOnly, nil},
		{"POST", "/v1/messages", "", nil},
		{"POST", "/api/v1/messages", "POST /api/v1/messages HTTP/1.1\r\n\r\n{\"to\":\"bob\",\"text\":\"hi\"}", nil},
		{"POST", "/api/generate", "POST /api/generate HTTP/1.1\r\n\r\n{\"model\":\"llama3\",\"prompt\":\"hi\"}", &LLMRequest{Operation: "text_completion", Model: "llama3"}},
		{"POST", "/api/generate", "POST /api/generate HTTP/1.1\r\n\r\n{\"template\":\"invoice\"}", nil},
		{"POST", "/generate_stream", "", &LLMRequest{Operation: "text_completion"}},
		{"POST", "/v2/models/llama/infer", "", &LLMRequest{Operation: "inference"}},
		{"POST", "/v2/models/llama/versions/2/generate_stream", "", &LLMRequest{Operation: "text_completion"}},
		{"POST", "/v2/models/llama/config", "", nil},
		{"POST", "/v1/models/sklearn-iris:predict", "", &LLMRequest{Operation: "inference"}},
		{"POST", "/inference.GRPCInferenceService/ModelInfer", "", &LLMRequest{Operation: "inference"}},
		{"POST", "/health", "", nil},
		{"POST", "", "", nil},
	} {
		assert.Equal(t, c.want, ParseLLMRequest(c.method, c.path, []byte(c.payload)), "%s %s", c.method, c.path)
	}
}
