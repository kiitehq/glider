package main

import (
	stdlog "log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kiitehq/glider/common/log"
	"github.com/kiitehq/glider/dns"
	"github.com/kiitehq/glider/ipset"
	"github.com/kiitehq/glider/proxy"
	"github.com/kiitehq/glider/rule"
	"github.com/kiitehq/glider/strategy"

	_ "github.com/kiitehq/glider/proxy/http"
	_ "github.com/kiitehq/glider/proxy/kcp"
	_ "github.com/kiitehq/glider/proxy/mixed"
	_ "github.com/kiitehq/glider/proxy/socks5"
	_ "github.com/kiitehq/glider/proxy/ss"
	_ "github.com/kiitehq/glider/proxy/ssr"
	_ "github.com/kiitehq/glider/proxy/tcptun"
	_ "github.com/kiitehq/glider/proxy/tls"
	_ "github.com/kiitehq/glider/proxy/udptun"
	_ "github.com/kiitehq/glider/proxy/uottun"
	_ "github.com/kiitehq/glider/proxy/vmess"
	_ "github.com/kiitehq/glider/proxy/ws"
)

// VERSION .
const VERSION = "0.6.10"

func main() {
	// read configs
	confInit()

	// setup a log func
	log.F = func(f string, v ...interface{}) {
		if conf.Verbose {
			stdlog.Printf(f, v...)
		}
	}

	// global rule dialer
	dialer := rule.NewDialer(conf.rules, strategy.NewDialer(conf.Forward, &conf.StrategyConfig))

	// ipset manager
	ipsetM, _ := ipset.NewManager(conf.rules)

	// check and setup dns server
	if conf.DNS != "" {
		d, err := dns.NewServer(conf.DNS, dialer, &conf.DNSConfig)
		if err != nil {
			log.Fatal(err)
		}

		// rule
		for _, r := range conf.rules {
			for _, domain := range r.Domain {
				if len(r.DNSServers) > 0 {
					d.SetServers(domain, r.DNSServers...)
				}
			}
		}

		// add a handler to update proxy rules when a domain resolved
		d.AddHandler(dialer.AddDomainIP)
		if ipsetM != nil {
			d.AddHandler(ipsetM.AddDomainIP)
		}

		d.Start()
	}

	// enable checkers
	dialer.Check()

	// Proxy Servers
	for _, listen := range conf.Listen {
		local, err := proxy.ServerFromURL(listen, dialer)
		if err != nil {
			log.Fatal(err)
		}

		go local.ListenAndServe()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
