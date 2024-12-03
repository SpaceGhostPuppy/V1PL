package scanner

import (
    "context"
    "encoding/json"
    "time"
    
    "github.com/google/uuid"
    "github.com/streadway/amqp"
)

// ScanRequest repräsentiert einen neuen Scan-Auftrag
type ScanRequest struct {
    ID          string    `json:"id"`
    Target      string    `json:"target"`
    ScanType    string    `json:"scan_type"` // "web" oder "network"
    Parameters  map[string]interface{} `json:"parameters"`
    CreatedAt   time.Time `json:"created_at"`
    Status      string    `json:"status"`
}

// Orchestrator verwaltet Scan-Aufträge
type Orchestrator struct {
    rabbitmq    *amqp.Connection
    channel     *amqp.Channel
    webQueue    string
    networkQueue string
}

// NewOrchestrator erstellt einen neuen Scan-Orchestrator
func NewOrchestrator(amqpURL string) (*Orchestrator, error) {
    conn, err := amqp.Dial(amqpURL)
    if err != nil {
        return nil, err
    }

    ch, err := conn.Channel()
    if err != nil {
        return nil, err
    }

    // Warteschlangen für verschiedene Scan-Typen deklarieren
    webQ, err := ch.QueueDeclare(
        "web_scans",  // Name
        true,         // Dauerhaft
        false,        // Löschen wenn unbenutzt
        false,        // Exklusiv
        false,        // Kein Warten
        nil,          // Argumente
    )
    if err != nil {
        return nil, err
    }

    networkQ, err := ch.QueueDeclare(
        "network_scans",
        true,
        false,
        false,
        false,
        nil,
    )
    if err != nil {
        return nil, err
    }

    return &Orchestrator{
        rabbitmq:     conn,
        channel:      ch,
        webQueue:     webQ.Name,
        networkQueue: networkQ.Name,
    }, nil
}

// SubmitScan plant einen neuen Scan ein
func (o *Orchestrator) SubmitScan(ctx context.Context, target string, scanType string, params map[string]interface{}) (*ScanRequest, error) {
    scan := &ScanRequest{
        ID:         uuid.New().String(),
        Target:     target,
        ScanType:   scanType,
        Parameters: params,
        CreatedAt:  time.Now(),
        Status:     "pending",
    }

    // Scan-Anfrage in JSON umwandeln
    body, err := json.Marshal(scan)
    if err != nil {
        return nil, err
    }

    // Passende Warteschlange basierend auf Scan-Typ auswählen
    queueName := o.webQueue
    if scanType == "network" {
        queueName = o.networkQueue
    }

    // Scan-Anfrage an Warteschlange senden
    err = o.channel.Publish(
        "",         // Exchange
        queueName,  // Routing-Schlüssel
        false,      // Obligatorisch
        false,      // Sofort
        amqp.Publishing{
            DeliveryMode: amqp.Persistent,
            ContentType:  "application/json",
            Body:        body,
        })

    if err != nil {
        return nil, err
    }

    return scan, nil
}

// Close beendet den Orchestrator ordnungsgemaes 
func (o *Orchestrator) Close() error {
    if err := o.channel.Close(); err != nil {
        return err
    }
    return o.rabbitmq.Close()
}
