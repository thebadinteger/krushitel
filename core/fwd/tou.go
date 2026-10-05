package fwd

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	touTypeData = 0x00
	touTypeSyn  = 0x01
	touTypeAck  = 0x02
	touTypeKA   = 0x03
	touTypeSrv  = 0x04

	touVersionNibble = 0x10

	touHdrSize      = 12
	touSynSize      = 20
	touAckSize      = 16
	touMaxDataLen   = 0xFFFF
	touMaxPacketLen = 0x10000
)

var errTouVersion = errors.New("invalid tou message, wrong version")
var errTouType = errors.New("invalid tou message, unknown type")
var errTouTruncated = errors.New("tou buffer truncated")

func touHeader(typ byte) byte {
	return touVersionNibble | (typ & 0x0F)
}

func touBuildSyn(session uint32) []byte {
	b := make([]byte, touSynSize)
	b[0] = touHeader(touTypeSyn)
	binary.BigEndian.PutUint32(b[4:8], session)
	return b
}

func touBuildAck(session, value uint32) []byte {
	b := make([]byte, touAckSize)
	b[0] = touHeader(touTypeAck)
	binary.BigEndian.PutUint32(b[4:8], session)
	binary.BigEndian.PutUint32(b[12:16], value)
	return b
}

func touBuildData(session uint32, payload []byte) ([]byte, error) {
	if len(payload) > touMaxDataLen {
		return nil, fmt.Errorf("tou payload too large: %d", len(payload))
	}
	b := make([]byte, touHdrSize+len(payload))
	b[0] = touHeader(touTypeData)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(payload)))
	binary.BigEndian.PutUint32(b[4:8], session)
	copy(b[touHdrSize:], payload)
	return b, nil
}

func touBuildKeepalive(session uint32) []byte {
	b := make([]byte, touHdrSize)
	b[0] = touHeader(touTypeKA)
	binary.BigEndian.PutUint32(b[4:8], session)
	return b
}

func touBuildService(session uint32) []byte {
	b := make([]byte, touHdrSize)
	b[0] = touHeader(touTypeSrv)
	binary.BigEndian.PutUint32(b[4:8], session)
	return b
}

func touFixedLen(firstByte byte) (int, bool) {
	if firstByte&0xF0 != touVersionNibble {
		return 0, false
	}
	switch firstByte & 0x0F {
	case touTypeSyn:
		return touSynSize, true
	case touTypeAck:
		return touAckSize, true
	case touTypeKA, touTypeSrv:
		return touHdrSize, true
	}
	return 0, false
}

func parseTouPacket(frame []byte) (typ byte, session uint32, payload []byte, total int, err error) {
	if len(frame) < 1 {
		return 0, 0, nil, 0, errTouTruncated
	}
	if frame[0]&0xF0 != touVersionNibble {
		return 0, 0, nil, 0, errTouVersion
	}
	typ = frame[0] & 0x0F
	switch typ {
	case touTypeData:
		if len(frame) < touHdrSize {
			return typ, 0, nil, 0, errTouTruncated
		}
		n := int(binary.BigEndian.Uint16(frame[2:4]))
		total = touHdrSize + n
		if total > touMaxPacketLen {
			return typ, 0, nil, 0, fmt.Errorf("tou packet too large: %d", total)
		}
		if len(frame) < total {
			return typ, 0, nil, total, errTouTruncated
		}
		session = binary.BigEndian.Uint32(frame[4:8])
		return typ, session, frame[touHdrSize:total], total, nil
	case touTypeSyn:
		if len(frame) < touSynSize {
			return typ, 0, nil, 0, errTouTruncated
		}
		session = binary.BigEndian.Uint32(frame[4:8])
		return typ, session, nil, touSynSize, nil
	case touTypeAck:
		if len(frame) < touAckSize {
			return typ, 0, nil, 0, errTouTruncated
		}
		session = binary.BigEndian.Uint32(frame[4:8])
		return typ, session, frame[12:16], touAckSize, nil
	case touTypeKA, touTypeSrv:
		if len(frame) < touHdrSize {
			return typ, 0, nil, 0, errTouTruncated
		}
		session = binary.BigEndian.Uint32(frame[4:8])
		return typ, session, nil, touHdrSize, nil
	}
	return typ, 0, nil, 0, errTouType
}
