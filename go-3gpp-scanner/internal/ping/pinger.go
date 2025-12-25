package ping

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"3gpp-scanner/internal/models"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Pinger handles connectivity testing
type Pinger struct {
	config *models.PingConfig
}

// NewPinger creates a new pinger
func NewPinger(config *models.PingConfig) *Pinger {
	if len(config.TCPPorts) == 0 {
		config.TCPPorts = []int{443, 4500} // Default ports for ePDG
	}
	return &Pinger{config: config}
}

// Ping tests connectivity to multiple FQDNs
func (p *Pinger) Ping(ctx context.Context, fqdns []string) ([]models.PingResult, error) {
	results := make([]models.PingResult, 0, len(fqdns))
	resultsMux := &sync.Mutex{}

	jobs := make(chan string, len(fqdns))
	for _, fqdn := range fqdns {
		jobs <- fqdn
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < p.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.worker(ctx, jobs, &results, resultsMux)
		}()
	}

	wg.Wait()
	return results, nil
}

// worker processes ping jobs
func (p *Pinger) worker(ctx context.Context, jobs <-chan string, results *[]models.PingResult, mux *sync.Mutex) {
	for fqdn := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			var result models.PingResult
			if p.config.Method == "tcp" {
				result = p.pingTCP(fqdn)
			} else {
				result = p.pingICMP(fqdn)
			}

			if p.config.Verbose || result.Success {
				mux.Lock()
				*results = append(*results, result)
				mux.Unlock()
			}
		}
	}
}

// pingICMP performs ICMP ping
func (p *Pinger) pingICMP(fqdn string) models.PingResult {
	result := models.PingResult{
		FQDN:      fqdn,
		Method:    "icmp",
		Timestamp: time.Now(),
	}

	// Resolve IP
	ips, err := net.LookupIP(fqdn)
	if err != nil {
		result.Error = fmt.Sprintf("DNS lookup failed: %v", err)
		return result
	}

	if len(ips) == 0 {
		result.Error = "No IP addresses found"
		return result
	}

	ip := ips[0]
	result.IP = ip.String()

	// Determine protocol
	var network string
	var proto int
	if ip.To4() != nil {
		network = "ip4:icmp"
		proto = 1 // ICMPv4
	} else {
		network = "ip6:ipv6-icmp"
		proto = 58 // ICMPv6
	}

	// Create ICMP connection
	conn, err := icmp.ListenPacket(network, "")
	if err != nil {
		result.Error = fmt.Sprintf("ICMP listen failed (need root?): %v", err)
		return result
	}
	defer conn.Close()

	// Set timeout
	conn.SetDeadline(time.Now().Add(p.config.Timeout))

	// Create ICMP message
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1234,
			Seq:  1,
			Data: []byte("3gpp-scanner"),
		},
	}

	if proto == 58 {
		msg.Type = ipv6.ICMPTypeEchoRequest
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		result.Error = fmt.Sprintf("ICMP marshal failed: %v", err)
		return result
	}

	// Send ping
	start := time.Now()
	_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: ip})
	if err != nil {
		result.Error = fmt.Sprintf("ICMP send failed: %v", err)
		return result
	}

	// Receive reply
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	latency := time.Since(start)

	if err != nil {
		result.Error = fmt.Sprintf("ICMP receive failed: %v", err)
		return result
	}

	// Parse reply
	_, err = icmp.ParseMessage(proto, reply[:n])
	if err != nil {
		result.Error = fmt.Sprintf("ICMP parse failed: %v", err)
		return result
	}

	result.Success = true
	result.Latency = latency
	return result
}

// pingTCP performs TCP connectivity check
func (p *Pinger) pingTCP(fqdn string) models.PingResult {
	result := models.PingResult{
		FQDN:      fqdn,
		Method:    "tcp",
		Timestamp: time.Now(),
	}

	// Try each configured port
	for _, port := range p.config.TCPPorts {
		address := fmt.Sprintf("%s:%d", fqdn, port)
		start := time.Now()

		conn, err := net.DialTimeout("tcp", address, p.config.Timeout)
		latency := time.Since(start)

		if err == nil {
			conn.Close()
			result.Success = true
			result.Latency = latency
			result.IP = address
			return result
		}
	}

	result.Error = fmt.Sprintf("All TCP ports unreachable: %v", p.config.TCPPorts)
	return result
}

// PingOne performs a single ping test
func (p *Pinger) PingOne(fqdn string) models.PingResult {
	if p.config.Method == "tcp" {
		return p.pingTCP(fqdn)
	}
	return p.pingICMP(fqdn)
}
