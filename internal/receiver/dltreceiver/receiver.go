package dltreceiver

import (
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

type dltReceiver struct {
	config       *Config
	nextConsumer consumer.Logs
	conn         net.Conn
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	logger       *zap.Logger
	parser       *DLTParser
}

func (r *dltReceiver) Start(ctx context.Context, _ component.Host) error {
	var err error

	r.parser = NewDLTParser()

	address := fmt.Sprintf("%s:%d", r.config.DaemonAddress, r.config.DaemonPort)
	r.conn, err = net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to DLT daemon at %s: %v", address, err)
	}

	ctx, r.cancel = context.WithCancel(ctx)
	r.wg.Add(1)
	go r.receive(ctx)

	return nil
}

func (r *dltReceiver) receive(ctx context.Context) {
	defer r.wg.Done()
	defer func() {
		if r.conn != nil {
			r.conn.Close()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := r.processNextMessage(); err != nil {
				if err == io.EOF || isClosedError(err) {
					r.logger.Info("Connection closed")
					return
				}
				r.logger.Error("Error processing message", zap.Error(err))
				if err := r.reconnect(); err != nil {
					r.logger.Error("Failed to reconnect", zap.Error(err))
					return
				}
			}
		}
	}
}

func (r *dltReceiver) processNextMessage() error {
	err := r.parser.parseMessage(r.conn)
	if err != nil {
		return err
	}

	msg := r.parser.parseToStructured()
	if msg == nil {
		return fmt.Errorf("failed to parse message")
	}

	logs := r.convertToLogs(msg)

	return r.nextConsumer.ConsumeLogs(context.Background(), logs)
}

func (r *dltReceiver) reconnect() error {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second
	maxAttempts := 5
	attempts := 0

	for {
		if attempts >= maxAttempts {
			return fmt.Errorf("max reconnection attempts reached")
		}

		r.logger.Info("Attempting to reconnect", zap.Int("attempt", attempts+1))

		if r.conn != nil {
			r.conn.Close()
		}

		conn, err := net.Dial("tcp", r.config.DaemonAddress)
		if err == nil {
			r.conn = conn
			r.logger.Info("Successfully reconnected")
			return nil
		}

		attempts++
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (r *dltReceiver) convertToLogs(message *DLTMessage) plog.Logs {
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()

	resource := resourceLogs.Resource()
	attrs := resource.Attributes()
	attrs.PutStr("receiver", "dlt")
	attrs.PutStr("dlt.daemon.address", r.config.DaemonAddress)
	attrs.PutStr("service.name", "dlt-receiver")

	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	scopeLogs.Scope().SetName("dlt.receiver")
	scopeLogs.Scope().SetVersion("1.0.0")

	logRecord := scopeLogs.LogRecords().AppendEmpty()
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	logRecord.SetObservedTimestamp(pcommon.NewTimestampFromTime(message.Timestamp))

	setSeverity(logRecord, message.LogLevel)

	logAttrs := logRecord.Attributes()

	// Core DLT attributes
	logAttrs.PutInt("dlt.timestamp", int64(message.DLTTimestamp))
	logAttrs.PutStr("dlt.ecu_id", message.ECUID)
	logAttrs.PutStr("dlt.application_id", message.ApplicationID)
	logAttrs.PutStr("dlt.context_id", message.ContextID)
	logAttrs.PutBool("dlt.verbose", message.IsVerbose)
	logAttrs.PutStr("dlt.message_type", message.MessageType)

	if message.LogLevel != "" {
		logAttrs.PutStr("dlt.log_level", message.LogLevel)
	}

	if message.ServiceID != 0 {
		logAttrs.PutInt("dlt.service_id", int64(message.ServiceID))
	}
	if message.ControlStatus != "" {
		logAttrs.PutStr("dlt.control_status", message.ControlStatus)
	}

	logRecord.Body().SetStr(message.Payload)

	if len(r.config.Extractors) > 0 {
		for _, extractor := range r.config.Extractors {
			if value, ok := extractValue(message.Payload, extractor); ok {
				logAttrs.PutDouble(extractor.FieldName, value)
			}
		}
	}

	return logs
}

func extractValue(payload string, rule ExtractorRule) (float64, bool) {
	re, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return 0, false
	}

	matches := re.FindStringSubmatch(payload)
	if len(matches) != 2 {
		return 0, false
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, false
	}

	return value, true
}

func setSeverity(logRecord plog.LogRecord, logLevel string) {
	switch logLevel {
	case "fatal":
		logRecord.SetSeverityNumber(plog.SeverityNumberFatal)
		logRecord.SetSeverityText("FATAL")
	case "error":
		logRecord.SetSeverityNumber(plog.SeverityNumberError)
		logRecord.SetSeverityText("ERROR")
	case "warn":
		logRecord.SetSeverityNumber(plog.SeverityNumberWarn)
		logRecord.SetSeverityText("WARN")
	case "info":
		logRecord.SetSeverityNumber(plog.SeverityNumberInfo)
		logRecord.SetSeverityText("INFO")
	case "debug":
		logRecord.SetSeverityNumber(plog.SeverityNumberDebug)
		logRecord.SetSeverityText("DEBUG")
	case "verbose":
		logRecord.SetSeverityNumber(plog.SeverityNumberTrace)
		logRecord.SetSeverityText("TRACE")
	default:
		logRecord.SetSeverityNumber(plog.SeverityNumberUnspecified)
		logRecord.SetSeverityText("UNSPECIFIED")
	}
}

func (r *dltReceiver) Shutdown(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	if r.conn != nil {
		r.conn.Close()
	}
	return nil
}

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "use of closed network connection"
}
