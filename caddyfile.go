package caddy_blacklist

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"strconv"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("blacklist", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var blacklist BlackList

	for h.Next() {
		for h.NextBlock(0) {
			opt := h.Val()
			switch opt {
			case "file":
				if !h.AllArgs(&blacklist.File) {
					return nil, h.Errf("invalid file: %q", blacklist.File)
				}
			case "threshold":
				var threshold string
				if !h.AllArgs(&threshold) {
					return nil, h.Errf("invalid threshold: %q", threshold)
				}
				t, err := strconv.Atoi(threshold)
				if err != nil {
					return nil, h.Errf("invalid threshold: %q", threshold)
				}
				blacklist.Threshold = t
			default:
				return nil, h.Errf("unrecognized option: %s", opt)
			}
		}
	}

	return &blacklist, nil
}
