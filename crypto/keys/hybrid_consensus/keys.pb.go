// Minimal hand-written proto boilerplate for the hybrid_consensus PubKey.
// Proto package: cosmos.crypto.hybrid_consensus_ed25519_mldsa44
// Message: PubKey  — single bytes field (field 1): ed25519(32)||mldsa44(1312)=1344 B
//
// This file deliberately mirrors the shape of crypto/keys/hybrid/keys.pb.go so
// that proto.RegisterType and the gogoproto Marshal/Unmarshal path work without
// running protoc (no .proto source is needed at runtime).
package hybrid_consensus

import (
	"fmt"
	"io"
	math "math"
	math_bits "math/bits"

	proto "github.com/cosmos/gogoproto/proto"
)

var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

const _ = proto.GoGoProtoPackageIsVersion3

// PubKey is the Cosmos SDK wrapper for the Project Aegis ADR-008 §F4 hybrid
// consensus public key.  Key = ed25519(32) || ml-dsa-44(1312) = 1344 bytes.
// It is stored in Cosmos SDK state (x/staking Validator.ConsensusPubkey) as a
// proto Any with type URL /cosmos.crypto.hybrid_consensus_ed25519_mldsa44.PubKey.
type PubKey struct {
	Key []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
}

func (m *PubKey) Reset()         { *m = PubKey{} }
func (*PubKey) ProtoMessage()    {}
func (*PubKey) Descriptor() ([]byte, []int) { return fileDescriptor_consHybridKeys, []int{0} }

func (m *PubKey) XXX_Unmarshal(b []byte) error { return m.Unmarshal(b) }
func (m *PubKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ConsHybridPubKey.Marshal(b, m, deterministic)
	}
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *PubKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConsHybridPubKey.Merge(m, src)
}
func (m *PubKey) XXX_Size() int                { return m.Size() }
func (m *PubKey) XXX_DiscardUnknown()          { xxx_messageInfo_ConsHybridPubKey.DiscardUnknown(m) }

var xxx_messageInfo_ConsHybridPubKey proto.InternalMessageInfo

var fileDescriptor_consHybridKeys = []byte{
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe2, 0xb2, 0x4c, 0xce, 0x2f, 0xce,
	0xcd, 0x2f, 0xd6, 0x4f, 0x2e, 0xaa, 0x2c, 0x28, 0xc9, 0xd7, 0xcf, 0xa8, 0x4c, 0x2a, 0xca, 0x4c,
	0x89, 0x4f, 0xce, 0xcf, 0x2b, 0x4e, 0xcd, 0x2b, 0x2e, 0x2d, 0x8e, 0x4f, 0x4d, 0x31, 0x32, 0x35,
	0x35, 0xb4, 0x8c, 0xcf, 0xcd, 0x49, 0x29, 0x4e, 0x34, 0x31, 0xd1, 0xcf, 0x4e, 0xad, 0x2c, 0xd6,
	0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xd2, 0x83, 0x68, 0xd5, 0x83, 0x68, 0xd5, 0x23, 0xa4, 0x55,
	0x49, 0x8a, 0x8b, 0x2d, 0xa0, 0x34, 0xc9, 0x3b, 0xb5, 0x52, 0x48, 0x80, 0x8b, 0x39, 0x3b, 0xb5,
	0x52, 0x82, 0x51, 0x81, 0x51, 0x83, 0x27, 0x08, 0xc4, 0x4c, 0x62, 0x03, 0x1b, 0x69, 0x0c, 0x08,
	0x00, 0x00, 0xff, 0xff, 0xa1, 0xf8, 0xb3, 0xc9, 0x8f, 0x00, 0x00, 0x00,
}

func (m *PubKey) GetKey() []byte {
	if m != nil {
		return m.Key
	}
	return nil
}

func init() {
	proto.RegisterType((*PubKey)(nil), "cosmos.crypto.hybrid_consensus_ed25519_mldsa44.PubKey")
}

// ---------------------------------------------------------------------- wire

func (m *PubKey) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *PubKey) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *PubKey) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Key) > 0 {
		i -= len(m.Key)
		copy(dAtA[i:], m.Key)
		i = encodeVarintConsHybridKeys(dAtA, i, uint64(len(m.Key)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintConsHybridKeys(dAtA []byte, offset int, v uint64) int {
	offset -= sovConsHybridKeys(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}

func (m *PubKey) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Key)
	if l > 0 {
		n += 1 + l + sovConsHybridKeys(uint64(l))
	}
	return n
}

func sovConsHybridKeys(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}

func (m *PubKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return errIntOverflowConsHybridKeys
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: PubKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: PubKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Key", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return errIntOverflowConsHybridKeys
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return errInvalidLengthConsHybridKeys
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return errInvalidLengthConsHybridKeys
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Key = append(m.Key[:0], dAtA[iNdEx:postIndex]...)
			if m.Key == nil {
				m.Key = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConsHybridKeys(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return errInvalidLengthConsHybridKeys
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}
	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func skipConsHybridKeys(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, errIntOverflowConsHybridKeys
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, errIntOverflowConsHybridKeys
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, errIntOverflowConsHybridKeys
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, errInvalidLengthConsHybridKeys
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, errUnexpectedEndOfGroupConsHybridKeys
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, errInvalidLengthConsHybridKeys
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	errInvalidLengthConsHybridKeys        = fmt.Errorf("proto: negative length found during unmarshaling")
	errIntOverflowConsHybridKeys          = fmt.Errorf("proto: integer overflow")
	errUnexpectedEndOfGroupConsHybridKeys = fmt.Errorf("proto: unexpected end of group")
)
