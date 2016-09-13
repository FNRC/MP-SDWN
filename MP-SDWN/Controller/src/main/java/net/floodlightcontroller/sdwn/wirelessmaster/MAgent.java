package net.floodlightcontroller.sdwn.wirelessmaster;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;






import org.projectfloodlight.openflow.protocol.OFFactories;
//import org.codehaus.jackson.map.annotate.JsonSerialize;
//import org.openflow.protocol.OFFlowMod;
//import org.openflow.protocol.OFMatch;
//import org.openflow.protocol.OFPort;
//import org.openflow.protocol.action.OFAction;
//import org.openflow.protocol.action.OFActionOutput;
//import org.openflow.util.U16;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.Collections;
import java.util.HashSet;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.util.MACAddress;

@JsonSerialize(using=MAgentSerializer.class)
class MAgent implements IMAgent 
{

	// Connect to control socket on MAgent
	private Socket MAgentSocket = null;
	private PrintWriter outBuf;
	private BufferedReader inBuf;
	private IOFSwitch ofSwitch;
	private InetAddress ipAddress;
	private long lastHeard;

	private ConcurrentSkipListSet<MClient> clientList = new ConcurrentSkipListSet<MClient>();

	// MAgent Handler strings
	private static final String READ_HANDLER_TABLE = "table";
	private static final String READ_HANDLER_RXSTATS = "rxstats";
	private static final String READ_HANDLER_SPECTRAL_SCAN = "spectral_scan";
	private static final String WRITE_HANDLER_ADD_VAP = "add_vap";
	private static final String WRITE_HANDLER_SET_VAP = "set_vap";
	private static final String WRITE_HANDLER_REMOVE_VAP = "remove_vap";
	private static final String WRITE_HANDLER_SUBSCRIPTIONS = "subscriptions";
	private static final String WRITE_HANDLER_SEND_PROBE_RESPONSE = "send_probe_response";
	private static final String WRITE_HANDLER_SPECTRAL_SCAN = "spectral_scan";
	private static final String ODIN_AGENT_ELEMENT = "odinagent";

	private final int RX_STAT_NUM_PROPERTIES = 5;
	private final int ODIN_AGENT_PORT = 6777;

	
	/**
	 * Probably need a better identifier
	 * 
	 * @return the agent's IP address
	 */
	public InetAddress getIpAddress() 
	{
		return ipAddress;
	}

	
	/**
	 * Returns timestamp of last heartbeat from agent
	 * 
	 * @return Timestamp
	 */
	public long getLastHeard()
	{
		return lastHeard;
	}

	
	/**
	 * Set the lastHeard timestamp of a client
	 * 
	 * @param t  timestamp to update lastHeard value
	 */
	public void setLastHeard(long t) 
	{
		this.lastHeard = t;
	}

	
	/**
	 * Probe the agent for a list of VAPs its hosting. This should only be used
	 * by the master when an agent registration to shield against master
	 * failures. The assumption is that when this is invoked, the controller has
	 * never heard about the agent before.
	 * 
	 * @return a list of MClient entities on the agent
	 */
	public Set<MClient> getSvapsRemote() 
	{
		ConcurrentSkipListSet<MClient> clients = new ConcurrentSkipListSet<MClient>();
		String handle = invokeReadHandler(READ_HANDLER_TABLE);

		if (handle == null) 
		{
			return clients; // empty list
		}

		String tableList[] = handle.split("\n");

		for (String entry : tableList) 
		{

			if (entry.equals(""))
				break;
			
			/* 
			 * Every entry looks like this:
			 * properties:  [0]       [1]         [2]         [3, 4, 5...]
			 *           <sta_mac> <ipv4addr> <svap bssid> <svap ssid list>
			 *
			 */
			String properties[] = entry.split(" ");
			MClient mc;
			Svap svap;
			try 
			{
				// First, get the list of all the SSIDs
				ArrayList<String> ssidList = new ArrayList<String>();
				for (int i = 3; i < properties.length; i++)
				{
					ssidList.add (properties[i]);
				}
				svap =  new Svap (MACAddress.valueOf(properties[2]), ssidList);
				mc = new MClient(MACAddress.valueOf(properties[0]),InetAddress.getByName(properties[1]), svap);
				Set<IMAgent> agents=new HashSet<IMAgent> ();
				agents.add(this);
				svap.setAgents(agents);
				clients.add(mc);
//System.out.println(properties[0]+properties[1]+properties[2]+properties[3]);			
			} 
			catch (UnknownHostException e) 
			{
				e.printStackTrace();
			}
		}

		clientList = clients;

		return clients;
	}

	
	/**
	 * Return a list of SVAPs that the master knows this agent is hosting.
	 * Between the time an agent has crashed and the master detecting the crash,
	 * this can return stale values.
	 * 
	 * @return a list of MClient entities on the agent
	 */
	public Set<MClient> getSvapsLocal() 
	{
		return clientList;
	}

	
	/**
	 * Retrive Rx-stats from the MAgent.
	 * 
	 * @return A map of stations' MAC addresses to a map of properties and
	 *         values.
	 */
	public Map<MACAddress, Map<String, String>> getRxStats() 
	{
		String stats = invokeReadHandler(READ_HANDLER_RXSTATS);
		
		Map<MACAddress, Map<String, String>> ret = new HashMap<MACAddress, Map<String, String>>();

		/*
		 * We basically get rows like this MAC_ADDR1 prop1:<value> prop2:<value>
		 * MAC_ADDR2 prop1:<value> prop2:<value>
		 */
		String arr[] = stats.split("\n");
		for (String elem : arr) 
		{
			String row[] = elem.split(" ");

			if (row.length != RX_STAT_NUM_PROPERTIES + 1) 
			{
				continue;
			}

			MACAddress eth = MACAddress.valueOf(row[0].toLowerCase());

			Map<String, String> innerMap = new HashMap<String, String>();

			for (int i = 1; i < RX_STAT_NUM_PROPERTIES + 1; i += 1) 
			{
				innerMap.put(row[i].split(":")[0], row[i].split(":")[1]);
			}

			ret.put(eth, Collections.unmodifiableMap(innerMap));
		}

		return Collections.unmodifiableMap(ret);
	}

	
	/**
	 * To be called only once, initialises a connection to the MAgent's
	 * control socket. We let the connection persist so as to save on
	 * setup/tear-down messages with every invocation of an agent. This will
	 * also help speedup handoffs.
	 * 
	 * @param host Click based MAgent host
	 * @param port Click based MAgent's control socket port
	 * @return 0 on success, -1 otherwise
	 */
	public int init(InetAddress host) 
	{
			IOFSwitch sw = this.getSwitch();
			
			//fix concurrency flaw
			if (sw == null)
			{
				return 0;
			}

			//OFFlowAdd.Builder flow2 = sw.getOFFactory().buildFlowAdd();
			OFFlowAdd.Builder flow2 = OFFactories.getFactory(OFVersion.OF_10).buildFlowAdd();
			Match.Builder match = OFFactories.getFactory(OFVersion.OF_10).buildMatch();
			ArrayList<OFAction> actionList = new ArrayList<OFAction>();
			//OFActionOutput.Builder action = sw.getOFFactory().actions().buildOutput();
			  OFActionOutput.Builder action = OFFactories.getFactory(OFVersion.OF_10).actions().buildOutput();
			match.setExact(MatchField.ETH_TYPE, EthType.IPv4);
			match.setExact(MatchField.IP_PROTO, IpProtocol.UDP);
			match.setExact(MatchField.UDP_DST,TransportPort.of(68) );
			action.setMaxLen(0xffFFffFF);
			action.setPort(OFPort.CONTROLLER);
			actionList.add(action.build());
			
			
			flow2.setPriority((short) 200);
			flow2.setMatch(match.build());
			flow2.setIdleTimeout((short) 0);
			flow2.setActions(actionList);
			
			
			
			/////////////****************************************************//////
			/*
			OFMatch match = new OFMatch();
			match.fromString("dl_type=0x0800,nw_proto=17,tp_dst=68");
			
			OFActionOutput actionOutput = new OFActionOutput ();
			actionOutput.setPort(OFPort.OFPP_CONTROLLER.getValue());
			actionOutput.setLength((short) OFActionOutput.MINIMUM_LENGTH);
			
			List<OFAction> actionList = new ArrayList<OFAction>();
			actionList.add(actionOutput);
			
		
			flow2.setCookie(67);
			flow2.setPriority((short) 200);
			flow2.setMatch(match);
			flow2.setIdleTimeout((short) 0);
			flow2.setActions(actionList);
	        flow2.setLength(U16.t(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
		}
			*/
			

		
		
		
		ofSwitch.write(flow2.build());
		
		try 
		{
			MAgentSocket = new Socket(host.getHostAddress(), ODIN_AGENT_PORT);
			outBuf = new PrintWriter(MAgentSocket.getOutputStream(), true);
			inBuf = new BufferedReader(new InputStreamReader(MAgentSocket.getInputStream()));
			ipAddress = host;
		} 
		catch (UnknownHostException e) 
		{
			e.printStackTrace();
			return -1;
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
			return -1;
		}

		return 0;
	}

	
	/**
	 * Get the IOFSwitch for this agent
	 * 
	 * @return ofSwitch
	 */
	public IOFSwitch getSwitch() 
	{
		return ofSwitch;
	}

	
	/**
	 * Set the IOFSwitch entity corresponding to this agent
	 * 
	 * @param sw the IOFSwitch entity for this agent
	 */
	public void setSwitch(IOFSwitch sw) 
	{
		ofSwitch = sw;
	}

	
	/**
	 * Remove a virtual access point from the AP corresponding to this agent
	 * 
	 * @param staHwAddr The STA's ethernet address
	 */
	public void removeClientSvap(MClient mc) 
	{
		invokeWriteHandler(WRITE_HANDLER_REMOVE_VAP, mc.getMacAddress()
				.toString());
		clientList.remove(mc);
	}

	
	/**
	 * Add a virtual access point to the AP corresponding to this agent
	 * 
	 * @param oc MClient entity
	 */
	public void addClientSvap(MClient mc) 
	{
		assert (mc.getSvap() != null);
		
		String ssidList = "";
		
		for (String ssid: mc.getSvap().getSsids()) 
		{
			ssidList += " " + ssid;
		}
		
		invokeWriteHandler(WRITE_HANDLER_ADD_VAP, mc.getMacAddress().toString()
				+ " " + mc.getIpAddress().getHostAddress() + " "
				+ mc.getSvap().getBssid().toString() + ssidList);
		clientList.add(mc);
	}

	
	/**
	 * Update a virtual access point with possibly new IP, BSSID, or SSID
	 * 
	 * @param oc MClient entity
	 */
	public void updateClientSvap(MClient mc) 
	{
		assert (mc.getSvap() != null);
		
		String ssidList = "";
		
		for (String ssid: mc.getSvap().getSsids()) 
		{
			ssidList += " " + ssid;
		}
		
		invokeWriteHandler(WRITE_HANDLER_SET_VAP, mc.getMacAddress().toString()
				+ " " + mc.getIpAddress().getHostAddress() + " "
				+ mc.getSvap().getBssid().toString() + ssidList);
	}

	
	/**
	 * Set subscriptions
	 * 
	 * @param subscriptions
	 * @param t timestamp to update lastHeard value
	 */
	public void setSubscriptions(String subscriptionList) 
	{
		invokeWriteHandler(WRITE_HANDLER_SUBSCRIPTIONS, subscriptionList);
	}

	
	/**
	 * Internal method to invoke a read handler on the OdinAgent
	 * 
	 * @param handlerName OdinAgent handler
	 * @return read-handler string
	 */
	private synchronized String invokeReadHandler(String handlerName) 
	{
		outBuf.println("READ " + ODIN_AGENT_ELEMENT + "." + handlerName);

		String line = "";

		try 
		{
			String data = null;

			while ((data = inBuf.readLine()).contains("DATA") == false) 
			{
				// skip all the crap that the Click control
				// socket tells us
			}

			int numBytes = Integer.parseInt(data.split(" ")[1]);

			while (numBytes != 0) 
			{
				numBytes--;
				char[] buf = new char[1];
				inBuf.read(buf);
				line = line + new String(buf);
			}

			return line;
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}

		return null;
	}

	
	/**
	 * Internal method to invoke a write handler of the MAgent
	 * 
	 * @param handlerName MAgent write handler name
	 * @param handlerText Write string
	 */
	private synchronized void invokeWriteHandler(String handlerName,
			String handlerText) 
	{
		outBuf.println("WRITE " + ODIN_AGENT_ELEMENT + "." + handlerName + " "
				+ handlerText);
		
	}


	@Override
	public void sendProbeResponse(MACAddress clientHwAddr, MACAddress bssid, Set<String> ssidList) 
	{
		StringBuilder sb = new StringBuilder();
		sb.append(clientHwAddr);
		sb.append(" ");
		sb.append(bssid);
		
		for (String ssid: ssidList) 
		{
			sb.append(" ");
			sb.append(ssid);
		}
		
		invokeWriteHandler(WRITE_HANDLER_SEND_PROBE_RESPONSE, sb.toString());
		
	}
}
