package net.floodlightcontroller.sdwn.wirelessmaster;

import java.net.InetAddress;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.sdwn.wirelessmaster.IMAgent;
import net.floodlightcontroller.sdwn.wirelessmaster.MClient;
import net.floodlightcontroller.util.MACAddress;

/**
 * 
 * Stub MAgent class to be used for testing. 
 */
class StubMAgent implements IMAgent 
{

	private IOFSwitch sw = null;
	private InetAddress ipAddr = null;
	private long lastHeard;
	private ConcurrentSkipListSet<MClient> clientList = new ConcurrentSkipListSet<MClient>();
	
	@Override
	public void addClientSvap(MClient mc) 
	{
		clientList.add(mc);
	}

	@Override
	public InetAddress getIpAddress() 
	{
		return ipAddr;
	}

	@Override
	public Map<MACAddress, Map<String, String>> getRxStats() 
	{
		return null;
	}

	@Override
	public IOFSwitch getSwitch() 
	{
		return sw;
	}

	@Override
	public Set<MClient> getSvapsRemote() 
	{
		return clientList;
	}

	@Override
	public int init(InetAddress host) 
	{
		this.ipAddr = host;
		
		return 0;
	}

	@Override
	public void removeClientSvap(MClient mc) 
	{
		clientList.remove(mc);
	}

	@Override
	public void setSwitch(IOFSwitch sw) 
	{
		this.sw = sw;
	}


	public long getLastHeard () 
	{
		return lastHeard;
	} 
	
	public void setLastHeard (long t) 
	{
		this.lastHeard = t;
	}

	@Override
	public Set<MClient> getSvapsLocal() 
	{
		return clientList;
	}

	@Override
	public void setSubscriptions(String subscriptionList) 
	{
		// Do nothing.
	}

	@Override
	public void updateClientSvap(MClient mc) 
	{		
	}

	@Override
	public void sendProbeResponse(MACAddress clientHwAddr, MACAddress bssid,
			Set<String> ssidLists) 
	{
	}
}