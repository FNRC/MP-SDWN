package net.floodlightcontroller.sdwn.wirelessmaster;

import java.util.ArrayList;
import java.util.List;
import java.net.InetAddress;
import java.util.*;

import org.projectfloodlight.openflow.protocol.OFMessage;

import net.floodlightcontroller.util.MACAddress;

//import org.openflow.protocol.OFMessage;

/**
 * This class represents an svap that comprises a
 * BSSID and a set of SSIDs on top of it.
 * 
 * @author Lalith Suresh <suresh.lalith@gmail.com>
 *
 */
public class Svap 
{
	private final MACAddress svapBssid;
	private final List<String> svapSsids;
	private Set<IMAgent> MAgents;
	private List<OFMessage> msgList = new ArrayList<OFMessage>();
	
	Svap(MACAddress bssid, List<String> ssidList) 
	{
		svapBssid = bssid;
		svapSsids = ssidList;
	}
	
	protected void setAgents(Set<IMAgent> agents) 
	{
		this.MAgents = agents;
	}
	
	// ***** Getters and setters ***** //
	
	public MACAddress getBssid() 
	{
		return svapBssid;
	}
	
	public List<String> getSsids() 
	{
		return svapSsids;
	}
	
	public Set<IMAgent> getAgents() 
	{
		return MAgents;
	}
	
	public List<OFMessage> getOFMessageList() 
	{
		return msgList;
	}
	
	public void setOFMessageList(List<OFMessage> msglist) 
	{
		this.msgList = msglist;
	}
	
	protected boolean IsInSet(final InetAddress MAgentAddr)
	{
		for(IMAgent ag:this.getAgents())
		{
			if(ag.getIpAddress().equals(MAgentAddr))
				return true;
		}
		return false;
	}
	
	protected boolean AgentsHaveSwitch()
	{
		for(IMAgent ag:this.getAgents())
		{
			if(ag.getSwitch() != null)
				return true;
		}
		return false;
	}
}
