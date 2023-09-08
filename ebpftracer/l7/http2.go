package l7

import (
	"encoding/binary"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	http2FrameHeaderLength = 9
	http2DecoderGcInterval = uint64(10 * time.Minute)
)

type Http2FrameHeader struct {
	Type     http2.FrameType
	Flags    http2.Flags
	Length   int
	StreamId uint32
}

type Http2Request struct {
	Method   string
	Path     string
	Scheme   string
	Status   Status
	Duration time.Duration

	kernelTime uint64
}

type Http2Parser struct {
	clientDecoder  *hpack.Decoder
	serverDecoder  *hpack.Decoder
	activeRequests map[uint32]*Http2Request
	lastGcTime     uint64
}

func NewHttp2Parser() *Http2Parser {
	return &Http2Parser{
		clientDecoder:  hpack.NewDecoder(4096, nil),
		serverDecoder:  hpack.NewDecoder(4096, nil),
		activeRequests: map[uint32]*Http2Request{},
	}
}

func (p *Http2Parser) Parse(method Method, payload []byte, kernelTime uint64) []Http2Request {
	if method == MethodHttp2ClientFrames {
		l := len(http2.ClientPreface)
		if len(payload) >= l && string(payload[:l]) == http2.ClientPreface {
			payload = payload[l:]
		}
	}
	if len(payload) == 0 {
		return nil
	}

	var decoder *hpack.Decoder
	statuses := map[uint32]Status{}
	offset := 0
	for {
		if len(payload)-offset < http2FrameHeaderLength {
			break
		}
		h := Http2FrameHeader{
			Length:   int(binary.BigEndian.Uint32(payload[offset:]) >> 8),
			Type:     http2.FrameType(payload[offset+3]),
			Flags:    http2.Flags(payload[offset+4]),
			StreamId: binary.BigEndian.Uint32(payload[offset+5:]) & (1<<31 - 1),
		}
		offset += http2FrameHeaderLength
		if h.Type != http2.FrameHeaders {
			if len(payload)-offset < h.Length {
				break
			}
			offset += h.Length
			continue
		}
		switch method {
		case MethodHttp2ClientFrames:
			req := p.activeRequests[h.StreamId]
			if req == nil {
				req = &Http2Request{kernelTime: kernelTime}
				p.activeRequests[h.StreamId] = req
			}
			decoder = p.clientDecoder
			decoder.SetEmitFunc(func(hf hpack.HeaderField) {
				switch hf.Name {
				case ":method":
					if req.Method == "" && isHttpMethod(hf.Value) {
						req.Method = hf.Value
					}
				case ":path":
					if req.Path == "" && isHttpPath(hf.Value) {
						req.Path = hf.Value
					}
				case ":scheme":
					if req.Scheme == "" && isHttpScheme(hf.Value) {
						req.Scheme = hf.Value
					}
				}
			})
		case MethodHttp2ServerFrames:
			if _, ok := statuses[h.StreamId]; !ok {
				statuses[h.StreamId] = 0
			}
			decoder = p.serverDecoder
			decoder.SetEmitFunc(func(hf hpack.HeaderField) {
				if hf.Name == ":status" {
					s, _ := strconv.Atoi(hf.Value)
					statuses[h.StreamId] = Status(s)
				}
			})
		}
		next := offset + h.Length
		if next > len(payload) {
			next = len(payload)
		}
		if _, err := decoder.Write(payload[offset:next]); err != nil {
			continue
		}
		offset = next
	}
	var res []Http2Request
	for streamId, status := range statuses {
		r := p.activeRequests[streamId]
		if r == nil {
			continue
		}
		r.Status = status
		r.Duration = time.Duration(kernelTime - r.kernelTime)
		res = append(res, *r)
		delete(p.activeRequests, streamId)
	}

	// GC
	if kernelTime-p.lastGcTime > http2DecoderGcInterval {
		if p.lastGcTime > 0 {
			for streamId, r := range p.activeRequests {
				if kernelTime-r.kernelTime > http2DecoderGcInterval {
					delete(p.activeRequests, streamId)
				}
			}
		}
		p.lastGcTime = kernelTime
	}

	return res
}

func isHttpMethod(s string) bool {
	switch s {
	case http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace:
		return true
	}
	return false
}

func isHttpPath(s string) bool {
	return strings.HasPrefix(s, "/") || s == "*"
}

func isHttpScheme(s string) bool {
	return s == "http" || s == "https"
}
