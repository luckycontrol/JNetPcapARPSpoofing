package model;

import java.util.Arrays;

public class ARP {

	private byte[] destinationMac = new byte[6];
	private byte[] sourceMac = new byte[6];
	private byte[] ethernetType = {0x08, 0x06}; // ARP
	private byte[] hardwareType = {0x00, 0x01}; // Ethernet
	private byte[] protocolType = {0x08, 0x00}; // IPv4
	private byte hardwareSize = 0x06; // MAC Size
	private byte protocolSize = 0x04; // IP Size
	private byte[] opcode = new byte[2];
	private byte[] senderMac = new byte[6];
	private byte[] senderIp = new byte[4];
	private byte[] targetMac = new byte[6];
	private byte[] targetIp = new byte[4];
	
	public void makeARPrequest(byte[] sourceMAC, byte[] senderIp, byte[] targetIp) {
		Arrays.fill(destinationMac, (byte)0xff); // Broadcast
		System.arraycopy(sourceMAC, 0, this.sourceMac, 0, 6);
		opcode[0] = 0x00; opcode[1] = 0x01; // Request
		System.arraycopy(sourceMAC, 0, this.senderMac, 0, 6);
		System.arraycopy(senderIp, 0, this.senderIp, 0, 4);
		Arrays.fill(targetMac, (byte)0x00); // Broadcast
		System.arraycopy(targetIp, 0, this.targetIp, 0, 4);
		}
	
	public void makeARPReply(byte[] destinationMac, byte[] sourceMac, byte[] senderMac,
			byte[] senderIp, byte[] targetMac, byte[] targetIp) {
		System.arraycopy(destinationMac, 0, this.destinationMac, 0, 6);
		System.arraycopy(sourceMac, 0, this.sourceMac, 0, 6);
		opcode[0] = 0x00; opcode[1] = 0x02; // Reply
		System.arraycopy(senderMac, 0, this.senderMac, 0, 6);
		System.arraycopy(senderIp, 0, this.senderIp, 0, 4);
		System.arraycopy(targetMac, 0, this.targetMac, 0, 6);
		System.arraycopy(targetIp, 0, this.targetIp, 0, 4);
		}
	
	public byte[] getPacket() {
		byte[] bytes = new byte[42];
		System.arraycopy(destinationMac, 0, bytes, 0, destinationMac.length);
		System.arraycopy(sourceMac, 0, bytes, 6, sourceMac.length);
		System.arraycopy(ethernetType, 0, bytes, 12, ethernetType.length);
		System.arraycopy(hardwareType, 0, bytes, 14, hardwareType.length);
		System.arraycopy(protocolType, 0, bytes, 16, protocolType.length);
		bytes[18] = hardwareSize;
		bytes[19] = protocolSize;
		System.arraycopy(opcode, 0, bytes, 20, opcode.length);
		System.arraycopy(senderMac, 0, bytes, 22, senderMac.length);
		System.arraycopy(senderIp, 0, bytes, 28, senderIp.length);
		System.arraycopy(targetMac, 0, bytes, 32, targetMac.length);
		System.arraycopy(targetIp, 0, bytes, 38, targetIp.length);
		return bytes;
		
	}
}
