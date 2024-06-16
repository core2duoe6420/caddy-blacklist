package caddy_blacklist

import (
	"bufio"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"go.uber.org/zap"
	"net"
	"os"
	"strings"
)

type Blocker interface {
	Block(ipv4 net.IP)
	Close()
}

type IptablesBlocker struct {
	handler *os.File
	tables  *iptables.IPTables
	logger  *zap.Logger
}

func NewBlocker(file string, logger *zap.Logger) *IptablesBlocker {
	tables, err := iptables.New()
	if err != nil {
		panic(err)
	}

	r, err := os.Open(file)
	if err == nil {
		defer r.Close()
		scanner := bufio.NewScanner(r)
		// optionally, resize scanner's capacity for lines over 64K, see next example
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			ip := net.ParseIP(scanner.Text())
			if ip == nil {
				panic(fmt.Errorf("invalid ip address: %s", line))
			}

			if e := blockIp(tables, ip); e != nil {
				panic(e)
			}
		}

	}

	handler, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	return &IptablesBlocker{
		handler: handler,
		tables:  tables,
		logger:  logger,
	}
}

func blockIp(tables *iptables.IPTables, ip net.IP) error {
	return tables.Append("filter", "INPUT", "--src", ip.String(), "-j", "DROP")
}

func (b *IptablesBlocker) Block(ipv4 net.IP) {
	if e := blockIp(b.tables, ipv4); e != nil {
		b.logger.Error("failed to block ip", zap.Error(e))
	}
	if _, e := b.handler.WriteString(ipv4.String() + "\n"); e != nil {
		b.logger.Error("failed to write to file", zap.Error(e))
	}
}

func (b *IptablesBlocker) Close() {
	if e := b.handler.Close(); e != nil {
		b.logger.Error("failed to close file", zap.Error(e))
	}
}
