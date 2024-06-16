package caddy_blacklist

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"net"
	"net/http"
	"sync"
)

func init() {
	caddy.RegisterModule(BlackList{})
}

type BlackList struct {
	File      string `json:"file,omitempty"`
	Threshold int    `json:"threshold,omitempty"`
	counter   *sync.Map
	blocker   Blocker
	logger    *zap.Logger
}

func (BlackList) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.blacklist",
		New: func() caddy.Module { return new(BlackList) },
	}
}

func (b *BlackList) Provision(ctx caddy.Context) error {
	b.logger = ctx.Logger(b)
	b.blocker = NewBlocker(b.File, b.logger)
	b.counter = &sync.Map{}

	if b.Threshold == 0 {
		b.Threshold = 5
	}

	return nil
}

func (b *BlackList) Cleanup() error {
	b.blocker.Close()
	return nil
}

func (b *BlackList) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fw := &blackListWriter{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		req:                   r,
		handler:               b,
	}
	return next.ServeHTTP(fw, r)
}

type blackListWriter struct {
	*caddyhttp.ResponseWriterWrapper
	req         *http.Request
	handler     *BlackList
	wroteHeader bool
}

func (bw *blackListWriter) blockUnauthorized() {
	ipStr, _, err := net.SplitHostPort(bw.req.RemoteAddr)
	if err != nil {
		bw.handler.logger.Error("invalid remote addr", zap.String("ip", bw.req.RemoteAddr))
		return
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		bw.handler.logger.Error("invalid ip", zap.String("ip", ipStr))
		return
	}

	if ip.IsLoopback() || ip.IsPrivate() {
		return
	}

	if c, ok := bw.handler.counter.Load(ipStr); ok {
		counter := c.(int) + 1
		if counter >= bw.handler.Threshold {
			bw.handler.blocker.Block(ip)
			bw.handler.logger.Info("blocked ip", zap.String("ip", ipStr))
			bw.handler.counter.Delete(ipStr)
		} else {
			bw.handler.counter.Store(ipStr, counter)
		}
	} else {
		bw.handler.counter.Store(ipStr, 1)
	}
}

func (bw *blackListWriter) WriteHeader(status int) {
	if bw.wroteHeader {
		return
	}
	bw.wroteHeader = true

	if status == http.StatusUnauthorized {
		bw.blockUnauthorized()
	}

	bw.ResponseWriterWrapper.WriteHeader(status)
}

func (bw *blackListWriter) Write(d []byte) (int, error) {
	if !bw.wroteHeader {
		bw.WriteHeader(http.StatusOK)
	}
	return bw.ResponseWriterWrapper.Write(d)
}

var (
	_ caddy.Provisioner  = (*BlackList)(nil)
	_ caddy.CleanerUpper = (*BlackList)(nil)

	_ http.ResponseWriter = (*blackListWriter)(nil)
)
