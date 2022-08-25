// This is a backup for we used to deal with proto just
// like in Elkeid. The decode function is self-coded by
// Elkeid-team. You can also get your own by reading the
// grpc.pb.go
package plugin

// func (p *Plugin) receiveData() (rec *proto.EncodedRecord, err error) {
// 	var l uint32
// 	err = binary.Read(p.reader, binary.LittleEndian, &l)
// 	if err != nil {
// 		return
// 	}
// 	_, err = p.reader.Discard(1)
// 	if err != nil {
// 		return
// 	}
// 	te := 1

// 	// pool is removed for temp
// 	// rec = pool.Get()
// 	rec = &proto.EncodedRecord{}
// 	var dt, ts, e int

// 	dt, e, err = readVarint(p.reader)
// 	if err != nil {
// 		return
// 	}
// 	_, err = p.reader.Discard(1)
// 	if err != nil {
// 		return
// 	}
// 	te += e + 1
// 	rec.DataType = int32(dt)

// 	ts, e, err = readVarint(p.reader)
// 	if err != nil {
// 		return
// 	}
// 	_, err = p.reader.Discard(1)
// 	if err != nil {
// 		return
// 	}
// 	te += e + 1
// 	rec.Timestamp = int64(ts)

// 	if uint32(te) < l {
// 		_, e, err = readVarint(p.reader)
// 		if err != nil {
// 			return
// 		}
// 		te += e
// 		ne := int(l) - te
// 		if cap(rec.Data) < ne {
// 			rec.Data = make([]byte, ne)
// 		} else {
// 			rec.Data = rec.Data[:ne]
// 		}
// 		_, err = io.ReadFull(p.reader, rec.Data)
// 		if err != nil {
// 			return
// 		}
// 	}
// 	// Incr for plugin status
// 	atomic.AddUint64(&p.txCnt, 1)
// 	atomic.AddUint64(&p.txBytes, uint64(l))
// 	return
// }

// func readVarint(r io.ByteReader) (int, int, error) {
// 	varint := 0
// 	eaten := 0
// 	for shift := uint(0); ; shift += 7 {
// 		if shift >= 64 {
// 			return 0, eaten, proto.ErrIntOverflowGrpc
// 		}
// 		b, err := r.ReadByte()
// 		if err != nil {
// 			return 0, eaten, err
// 		}
// 		eaten++
// 		varint |= int(b&0x7F) << shift
// 		if b < 0x80 {
// 			break
// 		}
// 	}
// 	return varint, eaten, nil
// }
