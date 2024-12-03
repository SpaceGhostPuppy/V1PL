package scanner

import (
    "context"
    "encoding/binary"
    "fmt"
    "net"
    "sync"
    "time"
    "encoding/json"
    
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/streadway/amqp"
)

// repräsentiert eine gefundene Schwachstelle
type Vulnerability struct {
    Type        string    `json:"type"`
    Severity    string    `json:"severity"`
    Description string    `json:"description"`
    Host        string    `json:"host"`
    Port        int       `json:"port"`
    Evidence    string    `json:"evidence"`
    Timestamp   time.Time `json:"timestamp"`
}

// ScanResult enthält die Ergebnisse eines Netzwerk-Scans
type ScanResult struct {

}

// NetzworkScanner implementiert die Netzwerk-Scanning Functionality
type NetworkScanner struct { 

}

// ScanConfig enthält die Konfiguration für den Scanner
type ScanConfig struct {

}

// NewNetworkScanner erstellet eine neue Instanz
func NewNetworkScanner(amqpURL string, config ScanConfig) (*NetworkScanner, error) {
  conn, err := amqp.Dial(amqpURL)
  if err != nil {
      return nil, fmt.Errorf("AMQP verbindung fehlgeschlagen: %v", err)
  }

  ch, err := conn.Channel()
  if err != nil {
      return nil, fmt.Errorf("AMQP channel erstellen fehlgeschlagen: %v", err)
  }

  // Queue für Netzwerk-Scans deklarieren
  _, err = ch.QueueDeclare(
      "network_scans",
      true,
      false,
      false,
      false,
      nil,
    )
    if err != nil {
      return nil, fmt.Errorf("AMQP channel erstellen fehlgeschlagen: %v", err)
    }

    return &NetworkScanner{
        rabbitmq:  conn,
        channel:   ch,
        results:   make(chan ScanResult),
        rateLimiter: time.NewTicker(config.RateLimit),
        timeout:  config.Timeout,
        concurrent:  config.Concurrent,
        logger:    NewLogger("network_scanner"),
    }, nil
}

// identifyService versucht den Service auf einem Port zu identifizieren
func identifyService(port int, banner string) string {
    commonPorts := map[int]string{
        21:   "FTP",
        22:   "SSH",
        23:   "Telnet",
        25:   "SMTP",
        80:   "HTTP",
        443:  "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
    }

    if service, exists := commonPorts[port]; exists {
        return service
    }

    // Banner-basierte Erkennung
    switch {
    case contains(banner, "SSH"):
        return "SSH"
    case contains(banner, "FTP"):
        return "FTP"
    case contains(banner, "HTTP"):
        return "HTTP"
    default:
        return "Unknown"
    }
}

// checkVulnerabilities prüft auf bekannte Schwachstellen
func checkVulnerabilities(service, banner string) *Vulnerability {
    vulnerabilities := map[string][]string{
        "SSH": {
            "SSH-1",
            "OpenSSH 4.",
            "OpenSSH 5.0",
        },
        "FTP": {
            "vsftpd 2.3.4",
            "ProFTPD 1.3.3",
        },
    }

    if patterns, exists := vulnerabilities[service]; exists {
        for _, pattern := range patterns {
            if contains(banner, pattern) {
                return &Vulnerability{
                    Type:        "Veraltete Version",
                    Severity:    "Hoch",
                    Description: fmt.Sprintf("Veraltete %s Version gefunden: %s", service, pattern),
                    Evidence:    banner,
                    Timestamp:   time.Now(),
                }
            }
        }
    }

    return nil
}

// ScanNetwork führt einen vollständigen Netzwerk-Scan durch
func (ns *NetworkScanner) ScanNetwork(ctx context.Context, target string, portRanges [][2]int) (*ScanResult, error) {
    result := &ScanResult{
        ID:        generateID(),
        Target:    target,
        StartTime: time.Now(),
        Services:  make(map[int]string),
    }

    // IP-Adressen auflösen
    ips, err := net.LookupIP(target)
    if err != nil {
        return nil, fmt.Errorf("IP-Auflösung fehlgeschlagen: %v", err)
    }

    var wg sync.WaitGroup
    portChan := make(chan int, ns.concurrent)

    // Worker für Port-Scans starten
    for i := 0; i < ns.concurrent; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for port := range portChan {
                select {
                case <-ns.rateLimiter.C:
                    if vuln, err := ns.scanPort(ctx, ips[0].String(), port); err == nil && vuln != nil {
                        ns.mutex.Lock()
                        result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
                        ns.mutex.Unlock()
                    }
                case <-ctx.Done():
                    return
                }
            }
        }()
    }

    // Ports in den Channel einfügen
    for _, portRange := range portRanges {
        for port := portRange[0]; port <= portRange[1]; port++ {
            select {
            case portChan <- port:
            case <-ctx.Done():
                close(portChan)
                return result, ctx.Err()
            }
        }
    }

    close(portChan)
    wg.Wait()

    result.EndTime = time.Now()
    return result, nil
}

// StartConsumer startet den Consumer für Scan-Aufträge
func (ns *NetworkScanner) StartConsumer() error {
    msgs, err := ns.channel.Consume(
        "network_scans",
        "",
        false,
        false,
        false,
        false,
        nil,
    )
    if err != nil {
        return fmt.Errorf("Consumer starten fehlgeschlagen: %v", err)
    }

    go func() {
        for msg := range msgs {
            var scanRequest struct {
                Target     string    `json:"target"`
                PortRanges [][2]int `json:"port_ranges"`
            }

            if err := json.Unmarshal(msg.Body, &scanRequest); err != nil {
                ns.logger.Error("Ungültiger Scan-Auftrag", err)
                msg.Nack(false, false)
                continue
            }

            ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
            result, err := ns.ScanNetwork(ctx, scanRequest.Target, scanRequest.PortRanges)
            cancel()

            if err != nil {
                ns.logger.Error("Scan fehlgeschlagen", err)
                msg.Nack(false, true)
                continue
            }

            // Ergebnisse speichern
            if err := ns.saveResults(result); err != nil {
                ns.logger.Error("Ergebnisse speichern fehlgeschlagen", err)
                msg.Nack(false, true)
                continue
            }

            msg.Ack(false)
        }
    }()

    return nil
}

// saveResults speichert die Scan-Ergebnisse
func (ns *NetworkScanner) saveResults(result *ScanResult) error {
    // Hier könnte die Implementierung für das Speichern in einer Datenbank erfolgen
    return nil
}

// Close schließt alle Verbindungen
func (ns *NetworkScanner) Close() error {
    ns.rateLimiter.Stop()
    if err := ns.channel.Close(); err != nil {
        return err
    }
    return ns.rabbitmq.Close()
}


















