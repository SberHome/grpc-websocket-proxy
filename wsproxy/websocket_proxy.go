package wsproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

const (
	defaultMethodOverrideParam = "method"
	defaultTokenCookieName     = "token"
	defaultAuthHeaderName      = "Authorization"
	defaultWriteDuration       = 100 * time.Millisecond
)

// RequestMutatorFunc can supply an alternate outgoing request.
type RequestMutatorFunc func(incoming *http.Request, outgoing *http.Request) *http.Request

// Proxy provides websocket transport upgrade to compatible endpoints.
type Proxy struct {
	h                      http.Handler
	maxRespBodyBufferBytes int
	methodOverrideParam    string
	tokenCookieName        string
	authHeaderName         string
	requestMutator         RequestMutatorFunc
	headerForwarder        func(header string) bool
	pingInterval           time.Duration
	pingWait               time.Duration
	pongWait               time.Duration
	writeDuration          time.Duration
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !websocket.IsWebSocketUpgrade(r) {
		p.h.ServeHTTP(w, r)
		return
	}
	p.proxy(w, r)
}

// Option allows customization of the proxy.
type Option func(*Proxy)

// WithMaxRespBodyBufferSize allows specification of a custom size for the
// buffer used while reading the response body. By default, the bufio.Scanner
// used to read the response body sets the maximum token size to MaxScanTokenSize.
func WithMaxRespBodyBufferSize(nBytes int) Option {
	return func(p *Proxy) {
		p.maxRespBodyBufferBytes = nBytes
	}
}

// WithMethodParamOverride allows specification of the special http parameter that is used in the proxied streaming request.
func WithMethodParamOverride(param string) Option {
	return func(p *Proxy) {
		p.methodOverrideParam = param
	}
}

// WithTokenCookieName allows specification of the cookie that is supplied as an upstream 'Authorization: Bearer' http header.
func WithTokenCookieName(param string) Option {
	return func(p *Proxy) {
		p.tokenCookieName = param
	}
}

// WithRequestMutator allows a custom RequestMutatorFunc to be supplied.
func WithRequestMutator(fn RequestMutatorFunc) Option {
	return func(p *Proxy) {
		p.requestMutator = fn
	}
}

// WithForwardedHeaders allows controlling which headers are forwarded.
func WithForwardedHeaders(fn func(header string) bool) Option {
	return func(p *Proxy) {
		p.headerForwarder = fn
	}
}

// WithPingControl allows specification of ping pong control. The interval
// parameter specifies the pingInterval between pings. The allowed wait time
// for a pong response is (pingInterval * 10) / 9.
func WithPingControl(interval time.Duration) Option {
	return func(proxy *Proxy) {
		proxy.pingInterval = interval
		proxy.pongWait = (interval * 10) / 9
		proxy.pingWait = proxy.pongWait / 6
	}
}

// WithAuthorizationHeaderName sets authorization header name for subprotocol parsing
func WithAuthorizationHeaderName(headerName string) Option {
	return func(proxy *Proxy) {
		proxy.authHeaderName = headerName
	}
}

func WithWriteDeadline(dur time.Duration) Option {
	return func(proxy *Proxy) {
		proxy.writeDuration = dur
	}
}

var defaultHeadersToForward = map[string]bool{
	"Origin":  true,
	"origin":  true,
	"Referer": true,
	"referer": true,
}

func defaultHeaderForwarder(header string) bool {
	return defaultHeadersToForward[header]
}

// WebsocketProxy attempts to expose the underlying handler as a bidi websocket stream with newline-delimited
// JSON as the content encoding.
//
// The HTTP Authorization header is either populated from the Sec-Websocket-Protocol field or by a cookie.
// The cookie name is specified by the TokenCookieName value.
//
// example:
//   Sec-Websocket-Protocol: Bearer, foobar
// is converted to:
//   Authorization: Bearer foobar
//
// Method can be overwritten with the MethodOverrideParam get parameter in the requested URL
func WebsocketProxy(h http.Handler, opts ...Option) http.Handler {
	p := &Proxy{
		h:                   h,
		methodOverrideParam: defaultMethodOverrideParam,
		tokenCookieName:     defaultTokenCookieName,
		authHeaderName:      defaultAuthHeaderName,
		headerForwarder:     defaultHeaderForwarder,
		writeDuration:       defaultWriteDuration,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// TODO(tmc): allow modification of upgrader settings?
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func (p *Proxy) proxy(w http.ResponseWriter, r *http.Request) {
	var responseHeader http.Header
	// If Sec-WebSocket-Protocol starts with "Bearer", respond in kind.
	// TODO(tmc): consider customizability/extension point here.
	if strings.HasPrefix(r.Header.Get("Sec-WebSocket-Protocol"), "Bearer") {
		responseHeader = http.Header{
			"Sec-WebSocket-Protocol": []string{"Bearer"},
		}
	}
	conn, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		log.Warn().Err(err).Msg("error upgrading websocket:")
		return
	}
	defer func() {
		_ = conn.Close()
	}()

	ctx, cancelFn := context.WithCancel(r.Context())
	defer cancelFn()

	requestBodyR, requestBodyW := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, r.Method, r.URL.String(), requestBodyR)
	if err != nil {
		log.Warn().Err(err).Msg("error preparing request:")
		return
	}
	if swsp := r.Header.Get("Sec-WebSocket-Protocol"); swsp != "" {
		request.Header.Set(p.authHeaderName, transformSubProtocolHeader(swsp))
	}
	for header := range r.Header {
		if p.headerForwarder(header) {
			request.Header.Set(header, r.Header.Get(header))
		}
	}
	// If token cookie is present, populate Authorization header from the cookie instead.
	if cookie, err := r.Cookie(p.tokenCookieName); err == nil {
		request.Header.Set(p.authHeaderName, "Bearer "+cookie.Value)
	}
	if m := r.URL.Query().Get(p.methodOverrideParam); m != "" {
		request.Method = m
	}

	if p.requestMutator != nil {
		request = p.requestMutator(r, request)
	}

	responseBodyR, responseBodyW := io.Pipe()
	response := newInMemoryResponseWriter(responseBodyW)
	go func() {
		<-ctx.Done()
		log.Debug().Msg("closing pipes")
		_ = requestBodyW.CloseWithError(io.EOF)
		_ = responseBodyW.CloseWithError(io.EOF)
		response.closed <- true
	}()

	go func() {
		defer cancelFn()
		p.h.ServeHTTP(response, request)
	}()

	// read loop -- take messages from websocket and write to http request
	go func() {
		if p.pingInterval > 0 && p.pingWait > 0 && p.pongWait > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(p.pongWait))
			conn.SetPongHandler(func(string) error {
				_ = conn.SetReadDeadline(time.Now().Add(p.pongWait))
				return nil
			})
		}
		defer func() {
			cancelFn()
			log.Debug().Msg("Closed")
		}()
		for {
			select {
			case <-ctx.Done():
				log.Debug().Msg("read loop done")
				return
			default:
			}
			log.Debug().Msg("[read] reading from socket.")
			_, payload, err := conn.ReadMessage()
			if err != nil {
				log.Debug().Str("err", err.Error()).Msg("error reading websocket message:")
				break
			}
			log.Debug().Str("payload", string(payload)).Msg("[read] read payload:")
			log.Debug().Msg("[read] writing to requestBody:")

			// TODO: Add some condition here. We should not try to write into a non-streaming input.
			n, err := requestBodyW.Write(payload)
			if err != nil {
				log.Warn().Err(err).Msg("[read] error writing message to upstream http server:")
				return
			}
			_, err = requestBodyW.Write([]byte("\n"))
			if err != nil {
				log.Warn().Err(err).Msg("[read] error writing message to upstream http server:")
				return
			}
			log.Debug().Int("n", n).Msg("[read] wrote to requestBody")
		}
	}()
	// ping write loop
	if p.pingInterval > 0 && p.pingWait > 0 && p.pongWait > 0 {
		go func() {
			ticker := time.NewTicker(p.pingInterval)
			defer func() {
				ticker.Stop()
				_ = conn.Close()
			}()
			for {
				select {
				case <-ctx.Done():
					log.Debug().Msg("ping loop done")
					return
				case <-ticker.C:
					_ = conn.SetWriteDeadline(time.Now().Add(p.pingWait))
					if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
						return
					}
				}
			}
		}()
	}
	// write loop -- take messages from response and write to websocket
	scanner := bufio.NewScanner(responseBodyR)

	// if maxRespBodyBufferSize has been specified, use custom buffer for scanner
	var scannerBuf []byte
	if p.maxRespBodyBufferBytes > 0 {
		scannerBuf = make([]byte, 0, 64*1024)
		scanner.Buffer(scannerBuf, p.maxRespBodyBufferBytes)
	}

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			log.Debug().Msg("gracefully stopping websocket")
			_ = conn.WriteControl(websocket.CloseMessage, nil, time.Now().Add(p.writeDuration))
			return
		default:
		}
		if len(scanner.Bytes()) == 0 {
			log.Warn().Err(scanner.Err()).Msg("[write] empty scan")
			continue
		}
		log.Debug().Str("text", scanner.Text()).Msg("[write] scanned")

		_ = conn.SetWriteDeadline(time.Now().Add(p.writeDuration))
		if err = conn.WriteMessage(websocket.TextMessage, scanner.Bytes()); err != nil {
			log.Info().Err(err).Msg("[write] error writing websocket message:")
			return
		}
	}
	if err := scanner.Err(); err != nil {
		log.Warn().Err(err).Msg("scanner err:")
	}
}

type inMemoryResponseWriter struct {
	io.Writer
	header http.Header
	code   int
	closed chan bool
}

func newInMemoryResponseWriter(w io.Writer) *inMemoryResponseWriter {
	return &inMemoryResponseWriter{
		Writer: w,
		header: http.Header{},
		closed: make(chan bool, 1),
	}
}

// IE and Edge do not delimit Sec-WebSocket-Protocol strings with spaces
func transformSubProtocolHeader(header string) string {
	tokens := strings.SplitN(header, "Bearer,", 2)

	if len(tokens) < 2 {
		return ""
	}

	return fmt.Sprintf("Bearer %v", strings.Trim(tokens[1], " "))
}

func (w *inMemoryResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}
func (w *inMemoryResponseWriter) Header() http.Header {
	return w.header
}
func (w *inMemoryResponseWriter) WriteHeader(code int) {
	w.code = code
}
func (w *inMemoryResponseWriter) CloseNotify() <-chan bool {
	return w.closed
}
func (w *inMemoryResponseWriter) Flush() {}
