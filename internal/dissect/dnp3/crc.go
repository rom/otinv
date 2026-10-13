package dnp3

// crcTable is the CRC-16/DNP table: polynomial 0x3D65 reflected (0xA6BC),
// initial value zero, final complement (IEEE 1815, 9.2.4.4).
var crcTable = func() [256]uint16 {
	var table [256]uint16
	for i := range table {
		crc := uint16(i)
		for range 8 {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
		table[i] = crc
	}
	return table
}()

// CRC returns the DNP3 frame CRC of data.
//
// It is exported because every DNP3 frame carries one per block and anything
// that builds, checks or crafts a frame needs it, test helpers included.
func CRC(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc = (crc >> 8) ^ crcTable[byte(crc)^b]
	}
	return ^crc
}
