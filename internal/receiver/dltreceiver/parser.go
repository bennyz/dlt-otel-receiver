package dltreceiver

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// DLT Protocol Constants
const (
	// Header Type (HTYP) flags
	DLT_HTYP_UEH  = 0x01 // use extended header
	DLT_HTYP_MSBF = 0x02 // MSB first
	DLT_HTYP_WEID = 0x04 // with ECU ID
	DLT_HTYP_WSID = 0x08 // with session ID
	DLT_HTYP_WTMS = 0x10 // with timestamp

	// Message Info (MSIN)
	DLT_MSIN_VERB = 0x01 // verbose
	DLT_MSIN_MSTP = 0x0e // message type
	DLT_MSIN_MTIN = 0xf0 // message type info
)

// Argument Types in payload
const (
	DLT_TYPE_INFO_TYLE = 0x0000000f // Length of standard data: 1 = 8bit, 2 = 16bit, 3 = 32 bit, 4 = 64 bit, 5 = 128 bit
	DLT_TYPE_INFO_BOOL = 0x00000010 // Boolean data
	DLT_TYPE_INFO_SINT = 0x00000020 // Signed integer data
	DLT_TYPE_INFO_UINT = 0x00000040 // Unsigned integer data
	DLT_TYPE_INFO_FLOA = 0x00000080 // Float data
	DLT_TYPE_INFO_ARAY = 0x00000100 // Array of standard types
	DLT_TYPE_INFO_STRG = 0x00000200 // String
	DLT_TYPE_INFO_RAWD = 0x00000400 // Raw data
	DLT_TYPE_INFO_VARI = 0x00000800 // Set, if additional information to a variable is available
	DLT_TYPE_INFO_FIXP = 0x00001000 // Set, if quantization and offset are added
	DLT_TYPE_INFO_TRAI = 0x00002000 // Set, if additional trace information is added
	DLT_TYPE_INFO_STRU = 0x00004000 // Struct
	DLT_TYPE_INFO_SCOD = 0x00038000 // coding of the type string: 0 = ASCII, 1 = UTF-8
)

const (
	DLT_TYLE_8BIT   = 0x00000001
	DLT_TYLE_16BIT  = 0x00000002
	DLT_TYLE_32BIT  = 0x00000003
	DLT_TYLE_64BIT  = 0x00000004
	DLT_TYLE_128BIT = 0x00000005
)

const (
	DLT_SCOD_ASCII = 0x00000000
	DLT_SCOD_UTF8  = 0x00008000
	DLT_SCOD_HEX   = 0x00010000
	DLT_SCOD_BIN   = 0x00018000
)

const (
	DLT_TYPE_LOG_FATAL   = 1
	DLT_TYPE_LOG_ERROR   = 2
	DLT_TYPE_LOG_WARN    = 3
	DLT_TYPE_LOG_INFO    = 4
	DLT_TYPE_LOG_DEBUG   = 5
	DLT_TYPE_LOG_VERBOSE = 6
)

const (
	DLT_LOG_INFO    = "log info"
	DLT_LOG_WARN    = "log warn"
	DLT_LOG_ERROR   = "log error"
	DLT_LOG_FATAL   = "log fatal"
	DLT_LOG_DEBUG   = "log debug"
	DLT_LOG_VERBOSE = "log verbose"
)

const (
	DLT_SERVICE_ID                                 = 0x00
	DLT_SERVICE_ID_SET_LOG_LEVEL                   = 0x01
	DLT_SERVICE_ID_SET_TRACE_STATUS                = 0x02
	DLT_SERVICE_ID_GET_LOG_INFO                    = 0x03
	DLT_SERVICE_ID_GET_DEFAULT_LOG_LEVEL           = 0x04
	DLT_SERVICE_ID_STORE_CONFIG                    = 0x05
	DLT_SERVICE_ID_RESET_TO_FACTORY_DEFAULT        = 0x06
	DLT_SERVICE_ID_SET_COM_INTERFACE_STATUS        = 0x07
	DLT_SERVICE_ID_SET_COM_INTERFACE_MAX_BANDWIDTH = 0x08
	DLT_SERVICE_ID_SET_VERBOSE_MODE                = 0x09
	DLT_SERVICE_ID_SET_MESSAGE_FILTERING           = 0x0A
	DLT_SERVICE_ID_SET_TIMING_PACKETS              = 0x0B
	DLT_SERVICE_ID_GET_LOCAL_TIME                  = 0x0C
	DLT_SERVICE_ID_USE_ECU_ID                      = 0x0D
	DLT_SERVICE_ID_USE_SESSION_ID                  = 0x0E
	DLT_SERVICE_ID_USE_TIMESTAMP                   = 0x0F
	DLT_SERVICE_ID_USE_EXTENDED_HEADER             = 0x10
)
const (
	UseExtendedHeader = 1 << iota
	MostSignificantByteFirst
	WithECUId
	WithSessionId
	WithTimestamp
)

// Message Type bits (MSTP) - 3 bits starting at bit 1
const (
	// Message Type bits (MSTP) - from protocol spec
	DLT_TYPE_LOG       = 0x00 // Log message type
	DLT_TYPE_APP_TRACE = 0x01 // Application trace message type
	DLT_TYPE_NW_TRACE  = 0x02 // Network trace message type
	DLT_TYPE_CONTROL   = 0x03 // Control message type

	// MSIN shifts
	DLT_MSIN_MSTP_SHIFT = 1 // shift right offset to get mstp value
	DLT_MSIN_MTIN_SHIFT = 4 // shift right offset to get mtin value

	// Control message types
	DLT_CONTROL_REQUEST  = 0x01
	DLT_CONTROL_RESPONSE = 0x02
	DLT_CONTROL_TIME     = 0x03
)

// Message Info bits
const (
	VERBOSE_MODE = 1 // Bit 0 is VERB
)

// DLT Type Info constants
const (
	TypeString      uint32 = 0x00020000
	TypeBool        uint32 = 0x00000010
	TypeSignedInt   uint32 = 0x00000020
	TypeUnsignedInt uint32 = 0x00000040
	TypeFloat       uint32 = 0x00000080
)

type DLTMessage struct {
	Timestamp      time.Time   `json:"timestamp"`
	DLTTimestamp   uint32      `json:"dlt_timestamp"`
	MessageCounter uint8       `json:"message_counter"`
	ECUID          string      `json:"ecu_id"`
	ApplicationID  string      `json:"application_id"`
	ContextID      string      `json:"context_id"`
	MessageType    string      `json:"message_type"`
	IsVerbose      bool        `json:"is_verbose"`
	ArgumentCount  uint8       `json:"argument_count"`
	Payload        string      `json:"payload"`
	LogLevel       string      `json:"log_level,omitempty"`
	ServiceID      uint32      `json:"service_id,omitempty"`
	ServiceName    string      `json:"service_name,omitempty"`
	ControlStatus  string      `json:"control_status,omitempty"`
	LogInfo        *DLTLogInfo `json:"log_info,omitempty"`
	Description    string      `json:"description,omitempty"`
}

type DLTArgument struct {
	TypeInfo uint32
	Data     []byte
}

// DLT Standard Header structure
type DLTHeader struct {
	HeaderType     uint8
	MessageCounter uint8
	Length         uint16
	ECUId          []byte
	SessionId      uint32
	Timestamp      uint32
}

type DLTExtendedHeader struct {
	MessageInfo   uint8
	NumberOfArgs  uint8
	ApplicationId []byte
	ContextId     []byte
}

type DLTParser struct {
	header      *DLTHeader
	extHeader   *DLTExtendedHeader
	payload     []byte
	messageType string
	verbose     bool
	logLevel    uint8
}

type DLTLogInfo struct {
	AppID       string
	ContextID   string
	LogLevel    uint8
	TraceState  uint8
	Description string
}

func NewDLTParser() *DLTParser {
	return &DLTParser{
		header:    &DLTHeader{},
		extHeader: &DLTExtendedHeader{},
	}
}

func readDLTHeader(r io.Reader) (*DLTHeader, error) {
	header := &DLTHeader{}

	headerStart := make([]byte, 4)
	if _, err := io.ReadFull(r, headerStart); err != nil {
		return nil, err
	}

	header.HeaderType = headerStart[0]
	header.MessageCounter = headerStart[1]
	header.Length = binary.BigEndian.Uint16(headerStart[2:])

	if header.HeaderType&WithECUId != 0 {
		header.ECUId = make([]byte, 4)
		if _, err := io.ReadFull(r, header.ECUId); err != nil {
			return nil, err
		}
	}

	if header.HeaderType&WithSessionId != 0 {
		sessionId := make([]byte, 4)
		if _, err := io.ReadFull(r, sessionId); err != nil {
			return nil, err
		}
		header.SessionId = binary.BigEndian.Uint32(sessionId)
	}

	if header.HeaderType&WithTimestamp != 0 {
		timestamp := make([]byte, 4)
		if _, err := io.ReadFull(r, timestamp); err != nil {
			return nil, err
		}
		header.Timestamp = binary.BigEndian.Uint32(timestamp)
	}

	return header, nil
}

func calculateHeaderSize(headerType uint8) int {
	size := 4 // Mandatory header size

	if headerType&WithECUId != 0 {
		size += 4
	}
	if headerType&WithSessionId != 0 {
		size += 4
	}
	if headerType&WithTimestamp != 0 {
		size += 4
	}

	return size
}

func (p *DLTParser) parseMessage(conn net.Conn) error {
	header, err := readDLTHeader(conn)
	if err != nil {
		return err
	}
	p.header = header

	payloadLength := int(header.Length) - calculateHeaderSize(header.HeaderType)
	if payloadLength <= 0 {
		return nil
	}

	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return fmt.Errorf("error reading payload: %v", err)
	}

	if header.HeaderType&UseExtendedHeader != 0 {
		extHeader, remaining, err := parseExtendedHeader(payload)
		if err != nil {
			return err
		}
		p.extHeader = extHeader
		p.payload = remaining

		p.setMessageTypeAndMode()
	} else {
		p.payload = payload
	}

	return nil
}

func parseExtendedHeader(payload []byte) (*DLTExtendedHeader, []byte, error) {
	if len(payload) < 10 {
		return nil, nil, fmt.Errorf("payload too short for extended header")
	}

	extHeader := &DLTExtendedHeader{
		MessageInfo:   payload[0],
		NumberOfArgs:  payload[1],
		ApplicationId: payload[2:6],
		ContextId:     payload[6:10],
	}

	return extHeader, payload[10:], nil
}

func getMsgType(messageInfo uint8) int {
	return int((messageInfo >> 1) & 0x07)
}

func getLogLevel(messageInfo uint8) uint8 {
	return (messageInfo >> 4) & 0x07
}

func getLogTypeString(logLevel uint8) string {
	switch logLevel {
	case DLT_TYPE_LOG_FATAL:
		return DLT_LOG_FATAL
	case DLT_TYPE_LOG_ERROR:
		return DLT_LOG_ERROR
	case DLT_TYPE_LOG_WARN:
		return DLT_LOG_WARN
	case DLT_TYPE_LOG_INFO:
		return DLT_LOG_INFO
	case DLT_TYPE_LOG_DEBUG:
		return DLT_LOG_DEBUG
	case DLT_TYPE_LOG_VERBOSE:
		return DLT_LOG_VERBOSE
	default:
		return "log unknown"
	}
}

func dltEndianGet32(htyp uint8, val uint32) uint32 {
	if (htyp & DLT_HTYP_MSBF) != 0 {
		return val // Big endian
	}
	// Little endian conversion
	return ((val & 0xFF000000) >> 24) |
		((val & 0x00FF0000) >> 8) |
		((val & 0x0000FF00) << 8) |
		((val & 0x000000FF) << 24)
}

func dltEndianGet16(htyp uint8, val uint16) uint16 {
	if (htyp & DLT_HTYP_MSBF) != 0 {
		// Big endian
		return val
	}
	// Little endian
	return ((val & 0xFF00) >> 8) | ((val & 0x00FF) << 8)
}

func parseVerbosePayload(payload []byte, numArgs uint8, htyp uint8) string {
	var messages []string
	ptr := payload
	remaining := len(payload)

	for i := uint8(0); i < numArgs; i++ {
		if remaining < 4 {
			break
		}

		// Read type info and convert based on endianness
		typeInfoTmp := binary.BigEndian.Uint32(ptr[:4])
		typeInfo := dltEndianGet32(htyp, typeInfoTmp)

		ptr = ptr[4:]
		remaining -= 4

		if msg, newPtr, err := parseArgument(typeInfo, ptr, remaining, htyp); err == nil {
			messages = append(messages, msg)
			bytesRead := len(ptr) - len(newPtr)
			ptr = newPtr
			remaining -= bytesRead
		} else {
			return fmt.Sprintf("%x", payload)
		}
	}

	if len(messages) > 0 {
		return strings.Join(messages, " ")
	}
	return fmt.Sprintf("%x", payload)
}

func parseArgument(typeInfo uint32, data []byte, dataLength int, htyp uint8) (string, []byte, error) {
	if dataLength < 2 {
		return "", data, fmt.Errorf("data too short")
	}

	if (typeInfo & DLT_TYPE_INFO_STRG) != 0 {
		coding := typeInfo & DLT_TYPE_INFO_SCOD
		if (coding != DLT_SCOD_ASCII) && (coding != DLT_SCOD_UTF8) {
			return "", data, fmt.Errorf("unsupported string encoding")
		}

		var length uint16
		var nameLength uint16
		ptr := data

		// Handle variable info
		if (typeInfo & DLT_TYPE_INFO_VARI) != 0 {
			if dataLength < 4 {
				return "", data, fmt.Errorf("data too short for var info")
			}

			// Read and convert name length based on endianness
			nameLengthTmp := binary.BigEndian.Uint16(ptr[:2])
			nameLength = dltEndianGet16(htyp, nameLengthTmp)

			ptr = ptr[2:]
			dataLength -= 2

			if nameLength > 0 {
				if dataLength < int(nameLength) {
					return "", data, fmt.Errorf("data too short for name")
				}
				ptr = ptr[nameLength:]
				dataLength -= int(nameLength)
			}
		}

		// Read and convert string length based on endianness
		lengthTmp := binary.BigEndian.Uint16(ptr[:2])
		length = dltEndianGet16(htyp, lengthTmp)

		ptr = ptr[2:]
		dataLength -= 2

		if dataLength < int(length) {
			return "", data, fmt.Errorf("data too short for string content")
		}

		str := string(ptr[:length-1])
		ptr = ptr[length:]

		return str, ptr, nil
	} else if (typeInfo & DLT_TYPE_INFO_BOOL) != 0 {
		if dataLength < 1 {
			return "", data, fmt.Errorf("data too short for bool")
		}
		value := data[0] != 0
		return fmt.Sprintf("%v", value), data[1:], nil
	} else if (typeInfo&DLT_TYPE_INFO_SINT) != 0 || (typeInfo&DLT_TYPE_INFO_UINT) != 0 {
		isSigned := (typeInfo & DLT_TYPE_INFO_SINT) != 0
		size := typeInfo & DLT_TYPE_INFO_TYLE

		var value interface{}
		var bytesRead int

		switch size {
		case DLT_TYLE_8BIT:
			if dataLength < 1 {
				return "", data, fmt.Errorf("data too short for int8")
			}
			if isSigned {
				value = int8(data[0])
			} else {
				value = data[0]
			}
			bytesRead = 1
		case DLT_TYLE_16BIT:
			if dataLength < 2 {
				return "", data, fmt.Errorf("data too short for int16")
			}
			tmp := binary.BigEndian.Uint16(data[:2])
			converted := dltEndianGet16(htyp, tmp)
			if isSigned {
				value = int16(converted)
			} else {
				value = converted
			}
			bytesRead = 2
		case DLT_TYLE_32BIT:
			if dataLength < 4 {
				return "", data, fmt.Errorf("data too short for int32")
			}
			tmp := binary.BigEndian.Uint32(data[:4])
			converted := dltEndianGet32(htyp, tmp)
			if isSigned {
				value = int32(converted)
			} else {
				value = converted
			}
			bytesRead = 4
		case DLT_TYLE_64BIT:
			if dataLength < 8 {
				return "", data, fmt.Errorf("data too short for int64")
			}
			var tmp uint64
			if (htyp & DLT_HTYP_MSBF) != 0 {
				tmp = binary.BigEndian.Uint64(data[:8])
			} else {
				tmp = binary.LittleEndian.Uint64(data[:8])
			}
			if isSigned {
				value = int64(tmp)
			} else {
				value = tmp
			}
			bytesRead = 8
		default:
			return "", data, fmt.Errorf("unsupported integer size")
		}

		return fmt.Sprintf("%v", value), data[bytesRead:], nil
	}

	return "", data, fmt.Errorf("unsupported type")
}

func parseGetLogInfoPayload(payload []byte) (string, error) {
	if len(payload) < 7 {
		return "", fmt.Errorf("payload too short")
	}

	payload = payload[1:]

	count := payload[0]
	payload = payload[1:]

	var result strings.Builder

	for i := uint8(0); i < count && len(payload) >= 6; i++ {
		appID := strings.TrimRight(string(payload[:4]), "\x00")
		contextID := strings.TrimRight(string(payload[4:6]), "\x00")
		payload = payload[6:]

		result.WriteString(fmt.Sprintf("AppID='%s' ContextID='%s'", appID, contextID))

		for len(payload) >= 2 {
			if len(payload) < 2 {
				break
			}

			strLen := binary.BigEndian.Uint16(payload[:2])
			payload = payload[2:]

			if strLen == 0xFFFF {
				continue
			}

			if len(payload) < int(strLen) {
				break
			}

			if strLen > 0 {
				desc := string(payload[:strLen])
				result.WriteString(fmt.Sprintf(" %s", desc))
				payload = payload[strLen:]
			}
		}

		if i < count-1 {
			result.WriteString(" | ")
		}
	}

	return result.String(), nil
}

func parseControlMessage(payload []byte) string {
	if len(payload) < 4 {
		return fmt.Sprintf("%x", payload)
	}

	actualServiceID := uint32(payload[0])
	serviceName := getServiceName(actualServiceID)

	if len(payload) <= 4 {
		return serviceName
	}

	var result strings.Builder
	result.WriteString(serviceName)

	if isControlResponse(payload) {
		status := getReturnTypeString(payload[4])
		result.WriteString(", ")
		result.WriteString(status)

		if len(payload) > 5 {
			result.WriteString(fmt.Sprintf(", %x", payload[5:]))
		}
	} else {
		result.WriteString(fmt.Sprintf(", %x", payload[4:]))
	}

	return result.String()
}

func getReturnTypeString(retval uint8) string {
	switch retval {
	case 0x00:
		return "ok"
	case 0x01:
		return "not_supported"
	case 0x02:
		return "error"
	case 0x03:
		return "perm_denied"
	case 0x04:
		return "warning"
	case 0x08:
		return "no_matching_context_id"
	default:
		return fmt.Sprintf("%.2x", retval)
	}
}

func isControlResponse(payload []byte) bool {
	if len(payload) < 1 {
		return false
	}

	mstp := (payload[0] & DLT_MSIN_MSTP) >> DLT_MSIN_MSTP_SHIFT
	mtin := (payload[0] & DLT_MSIN_MTIN) >> DLT_MSIN_MTIN_SHIFT

	return mstp == DLT_TYPE_CONTROL && mtin == DLT_CONTROL_RESPONSE
}

func getServiceName(id uint32) string {
	switch id {
	case DLT_SERVICE_ID:
		return ""
	case DLT_SERVICE_ID_SET_LOG_LEVEL:
		return "set_log_level"
	case DLT_SERVICE_ID_SET_TRACE_STATUS:
		return "set_trace_status"
	case DLT_SERVICE_ID_GET_LOG_INFO:
		return "get_log_info"
	case DLT_SERVICE_ID_GET_DEFAULT_LOG_LEVEL:
		return "get_default_log_level"
	case DLT_SERVICE_ID_STORE_CONFIG:
		return "store_config"
	case DLT_SERVICE_ID_RESET_TO_FACTORY_DEFAULT:
		return "reset_to_factory_default"
	case DLT_SERVICE_ID_SET_COM_INTERFACE_STATUS:
		return "set_com_interface_status"
	case DLT_SERVICE_ID_SET_COM_INTERFACE_MAX_BANDWIDTH:
		return "set_com_interface_max_bandwidth"
	case DLT_SERVICE_ID_SET_VERBOSE_MODE:
		return "set_verbose_mode"
	case DLT_SERVICE_ID_SET_MESSAGE_FILTERING:
		return "set_message_filtering"
	case DLT_SERVICE_ID_SET_TIMING_PACKETS:
		return "set_timing_packets"
	case DLT_SERVICE_ID_GET_LOCAL_TIME:
		return "get_local_time"
	case DLT_SERVICE_ID_USE_ECU_ID:
		return "use_ecu_id"
	case DLT_SERVICE_ID_USE_SESSION_ID:
		return "use_session_id"
	case DLT_SERVICE_ID_USE_TIMESTAMP:
		return "use_timestamp"
	case DLT_SERVICE_ID_USE_EXTENDED_HEADER:
		return "use_extended_header"
	default:
		return fmt.Sprintf("service(%d)", id)
	}
}

func (p *DLTParser) setMessageTypeAndMode() {
	p.verbose = (p.extHeader.MessageInfo & VERBOSE_MODE) != 0

	msgType := getMsgType(p.extHeader.MessageInfo)
	switch msgType {
	case DLT_TYPE_LOG:
		p.messageType = "log"
		p.logLevel = getLogLevel(p.extHeader.MessageInfo)
	case DLT_TYPE_APP_TRACE:
		p.messageType = "app_trace"
	case DLT_TYPE_NW_TRACE:
		p.messageType = "nw_trace"
	case DLT_TYPE_CONTROL:
		p.messageType = "control"
	default:
		p.messageType = fmt.Sprintf("type_%d", msgType)
	}
}

func (p *DLTParser) parseToStructured() *DLTMessage {
	msg := &DLTMessage{
		Timestamp:      time.Now(),
		DLTTimestamp:   p.header.Timestamp,
		MessageCounter: p.header.MessageCounter,
		ECUID:          string(bytes.TrimRight(p.header.ECUId, "\x00")),
		IsVerbose:      p.verbose,
		MessageType:    p.messageType,
	}

	if p.extHeader != nil {
		msg.ApplicationID = string(bytes.TrimRight(p.extHeader.ApplicationId, "\x00"))
		msg.ContextID = string(bytes.TrimRight(p.extHeader.ContextId, "\x00"))
		msg.ArgumentCount = p.extHeader.NumberOfArgs
	}

	if msg.MessageType == "control" {
		msg.Payload = parseControlMessage(p.payload)
	} else if msg.MessageType == "log" {
		msg.LogLevel = getLogLevelString(p.logLevel)
		if p.verbose {
			msg.Payload = parseLogPayload(p.payload, p.extHeader.NumberOfArgs, p.header.HeaderType)
		} else {
			msg.Payload = fmt.Sprintf("%x", p.payload)
		}
	} else {
		if p.verbose {
			msg.Payload = parseVerbosePayload(p.payload, p.extHeader.NumberOfArgs, p.header.HeaderType)
		} else {
			msg.Payload = fmt.Sprintf("%x", p.payload)
		}
	}

	return msg
}

func parseLogPayload(payload []byte, numArgs uint8, htyp uint8) string {
	var messages []string
	ptr := payload
	remaining := len(payload)

	for i := uint8(0); i < numArgs; i++ {
		if remaining < 4 {
			break
		}

		typeInfoTmp := binary.BigEndian.Uint32(ptr[:4])
		typeInfo := dltEndianGet32(htyp, typeInfoTmp)

		ptr = ptr[4:]
		remaining -= 4

		if msg, newPtr, err := parseArgument(typeInfo, ptr, remaining, htyp); err == nil {
			messages = append(messages, msg)
			bytesRead := len(ptr) - len(newPtr)
			ptr = newPtr
			remaining -= bytesRead
		} else {
			return fmt.Sprintf("%x", payload)
		}
	}

	if len(messages) > 0 {
		return strings.Join(messages, " ")
	}
	return fmt.Sprintf("%x", payload)
}

func getLogLevelString(level uint8) string {
	switch level {
	case DLT_TYPE_LOG_FATAL:
		return "fatal"
	case DLT_TYPE_LOG_ERROR:
		return "error"
	case DLT_TYPE_LOG_WARN:
		return "warn"
	case DLT_TYPE_LOG_INFO:
		return "info"
	case DLT_TYPE_LOG_DEBUG:
		return "debug"
	case DLT_TYPE_LOG_VERBOSE:
		return "verbose"
	default:
		return "unknown"
	}
}
