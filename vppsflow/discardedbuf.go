package vppsflow

type DiscardedPacket struct {
	Header                 []byte
	HwTrapGroup            string
	HwTrapTrap             string
	LinuxDropMonitorReason string
}
