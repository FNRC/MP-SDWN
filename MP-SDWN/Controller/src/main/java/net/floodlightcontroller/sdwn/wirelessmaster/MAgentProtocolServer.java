package net.floodlightcontroller.sdwn.wirelessmaster;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.util.MACAddress;

class MAgentProtocolServer implements Runnable 
{
    protected static Logger log = LoggerFactory.getLogger(MAgentProtocolServer.class);

	// SDWN Message types
	private final String SDWN_MSG_PING = "ping";
	private final String SDWN_MSG_PROBE = "probe";
	private final String SDWN_MSG_PUBLISH = "publish";

	private final int SDWN_SERVER_PORT;
	
	private DatagramSocket controllerSocket;
	private final ExecutorService executor;
	private final WirelessMaster wirelessMaster;

	public MAgentProtocolServer (WirelessMaster wm, int port, ExecutorService executor) 
	{
		this.wirelessMaster = wm; 
		this.SDWN_SERVER_PORT = port;
		this.executor = executor;
	}
	
	@Override
	public void run() 
	{
		
		try 
		{
			controllerSocket = new DatagramSocket(SDWN_SERVER_PORT);
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		
		while(true)	
		{
			
			try 
			{
				final byte[] receiveData = new byte[1024]; // We can probably live with less
				final DatagramPacket receivedPacket = new DatagramPacket(receiveData, receiveData.length);
				controllerSocket.receive(receivedPacket);
				executor.execute(new MAgentConnectionHandler(receivedPacket));
			}
			catch (IOException e) 
			{
				log.error("controllerSocket.accept() failed: " + SDWN_SERVER_PORT);
				e.printStackTrace();
				System.exit(-1);
			}
		}
	}
	
	/** Protocol handlers **/
	
	private void receivePing (final InetAddress MAgentAddr) 
	{
		wirelessMaster.receivePing(MAgentAddr);
	}
	
	private void receiveProbe (final InetAddress MAgentAddr, final MACAddress clientHwAddress, final String ssid)
	{
		wirelessMaster.receiveProbe(MAgentAddr, clientHwAddress, ssid);
	}
	
	private void receivePublish (final MACAddress clientHwAddress, final InetAddress MAgentAddr, final Map<Long, Long> subscriptionIds) 
	{
		wirelessMaster.receivePublish(clientHwAddress, MAgentAddr, subscriptionIds);
	}
	
	private class MAgentConnectionHandler implements Runnable 
	{
		final DatagramPacket receivedPacket;
		
		public MAgentConnectionHandler(final DatagramPacket dp) 
		{
			receivedPacket = dp;
		}
		
		// Agent message handler
		public void run() 
		{			
			final String msg = new String(receivedPacket.getData()).trim().toLowerCase();
			final String[] fields = msg.split(" ");
			final String msg_type = fields[0];
			final InetAddress MAgentAddr = receivedPacket.getAddress();
            
            if (msg_type.equals(SDWN_MSG_PING)) 
            {
            	receivePing(MAgentAddr);
            }
            else if (msg_type.equals(SDWN_MSG_PROBE)) 
            {
            	// 2nd part of message should contain
            	// the STA's MAC address
            	final String staAddress = fields[1];
            	String ssid = "";
            	
            	if (fields.length > 2) 
            	{
            		//SSID is specified in the scan
            		ssid = msg.substring(SDWN_MSG_PROBE.length() + staAddress.length() + 2);
            	}

            	receiveProbe(MAgentAddr, MACAddress.valueOf(staAddress), ssid);
            }
            else if (msg_type.equals(SDWN_MSG_PUBLISH)) 
            {
            	final String staAddress = fields[1];
            	final int count = Integer.parseInt(fields[2]);
            	final Map<Long, Long> matchingIds = new HashMap<Long,Long> ();
     
            	for (int i = 0; i < count; i++) 
            	{
            		matchingIds.put(Long.parseLong(fields[3 + i].split(":")[0]),
            				Long.parseLong(fields[3 + i].split(":")[1]));
            	}
            	
            	receivePublish(MACAddress.valueOf(staAddress), MAgentAddr, matchingIds);
            }
		}
	}
}
