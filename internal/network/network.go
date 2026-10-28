// Package network collects low-level network signals for an audit target.
package network

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/storage"
)

const timeout = 1 * time.Second

var defaultPorts = []int{
	20, 21, 22, 25, 53, 80, 110, 143, 443, 445,
	465, 587, 993, 995, 1433, 1521, 2049, 2375, 2376,
	3000, 3306, 3389, 5000, 5432, 5601, 5672, 5900,
	6379, 8000, 8008, 8080, 8081, 8088, 8443, 8888,
	9000, 9200, 9300, 11211, 15672, 27017,
}

type Scanner struct {
	store *storage.Store
}

func New(store *storage.Store) *Scanner {
	return &Scanner{store: store}
}

func (s *Scanner) Run(auditRunID, targetURL string) (*models.NetworkResult, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("host missing from URL")
	}

	result := &models.NetworkResult{
		AuditRunID: auditRunID,
		Host:       host,
		Scheme:     u.Scheme,
		CheckedAt:  time.Now(),
	}

	result.DNS = lookupDNS(host)
	result.Ports = scanPorts(host, portsForURL(u))
	if u.Scheme == "https" || hasOpenPort(result.Ports, 443) {
		result.TLS = inspectTLS(host, tlsPortForURL(u))
	}

	s.store.SaveNetwork(result)
	return result, nil
}

func lookupDNS(host string) models.DNSRecords {
	var records models.DNSRecords

	if ips, err := net.LookupIP(host); err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				records.A = append(records.A, ip.String())
			} else {
				records.AAAA = append(records.AAAA, ip.String())
			}
		}
		sort.Strings(records.A)
		sort.Strings(records.AAAA)
	}
	if cname, err := net.LookupCNAME(host); err == nil {
		records.CNAME = strings.TrimSuffix(cname, ".")
	}
	if mx, err := net.LookupMX(host); err == nil {
		for _, r := range mx {
			records.MX = append(records.MX, strings.TrimSuffix(r.Host, "."))
		}
		sort.Strings(records.MX)
	}
	if txt, err := net.LookupTXT(host); err == nil {
		records.TXT = append(records.TXT, txt...)
		sort.Strings(records.TXT)
	}

	return records
}

func portsForURL(u *url.URL) []int {
	ports := append([]int{}, defaultPorts...)
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			ports = append(ports, n)
		}
	}
	return uniquePorts(ports)
}

func uniquePorts(ports []int) []int {
	seen := make(map[int]bool)
	var out []int
	for _, p := range ports {
		if p <= 0 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func scanPorts(host string, ports []int) []models.PortProbe {
	dialer := net.Dialer{Timeout: timeout}
	probes := make([]models.PortProbe, 0, len(ports))
	for _, port := range ports {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			probes = append(probes, models.PortProbe{
				Port:     port,
				Protocol: "tcp",
				Service:  serviceName(port),
				Open:     false,
				Error:    err.Error(),
			})
			continue
		}
		conn.Close()
		probes = append(probes, models.PortProbe{
			Port:     port,
			Protocol: "tcp",
			Service:  serviceName(port),
			Open:     true,
		})
	}
	return probes
}

func serviceName(port int) string {
	services := map[int]string{
		20:    "ftp-data",
		21:    "ftp",
		22:    "ssh",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		465:   "smtps",
		587:   "smtp-submission",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		2049:  "nfs",
		2375:  "docker-api",
		2376:  "docker-api-tls",
		3000:  "dev-http",
		3306:  "mysql",
		3389:  "rdp",
		5000:  "dev-http",
		5432:  "postgresql",
		5601:  "kibana",
		5672:  "amqp",
		5900:  "vnc",
		6379:  "redis",
		8000:  "http-alt",
		8008:  "http-alt",
		8080:  "http-proxy",
		8081:  "http-alt",
		8088:  "http-alt",
		8443:  "https-alt",
		8888:  "http-alt",
		9000:  "app-server",
		9200:  "elasticsearch",
		9300:  "elasticsearch-transport",
		11211: "memcached",
		15672: "rabbitmq-management",
		27017: "mongodb",
	}
	if name, ok := services[port]; ok {
		return name
	}
	return "unknown"
}

func tlsPortForURL(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	return 443
}

func inspectTLS(host string, port int) *models.TLSInfo {
	info := &models.TLSInfo{Checked: true}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(&dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		info.Error = "no peer certificate"
		return info
	}

	cert := state.PeerCertificates[0]
	now := time.Now()
	info.Valid = now.After(cert.NotBefore) && now.Before(cert.NotAfter)
	info.Version = tlsVersionName(state.Version)
	info.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	info.Subject = cert.Subject.String()
	info.Issuer = cert.Issuer.String()
	info.NotBefore = cert.NotBefore
	info.NotAfter = cert.NotAfter
	info.DNSNames = cert.DNSNames
	info.DaysToExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
	return info
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%x)", version)
	}
}

func hasOpenPort(ports []models.PortProbe, port int) bool {
	for _, p := range ports {
		if p.Port == port && p.Open {
			return true
		}
	}
	return false
}
