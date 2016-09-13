package net.floodlightcontroller.sdwn.wirelessmaster;


import java.net.InetAddress;
import java.util.Map;
import java.util.Set;

//import org.codehaus.jackson.map.annotate.JsonSerialize;


import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.util.MACAddress;

@JsonSerialize(using=MAgentSerializer.class)
public interface IMAgent 
{

	
	/**
	 * Probably need a better identifier
	 * @return the agent's IP address
	 */
	public InetAddress getIpAddress ();
	
	
	/**
	 * Get a list of VAPs that the agent is hosting
	 * @return a list of MClient entities on the agent
	 */
	public Set<MClient> getSvapsRemote ();
	
	
	/**
	 * Return a list of SVAPs that the master knows this
	 * agent is hosting. Between the time an agent has
	 * crashed and the master detecting the crash, this
	 * can return stale values.
	 * 
	 * @return a list of MClient entities on the agent
	 */
	public Set<MClient> getSvapsLocal ();
	
	
	/**
	 * Retrive Rx-stats from the MAgent.
	 * 
	 *  @return A map of stations' MAC addresses to a map
	 *  of properties and values.
	 */
	public Map<MACAddress, Map<String, String>> getRxStats ();
	
	
	/**
	 * To be called only once, intialises a connection to the MAgent's
	 * control socket. We let the connection persist so as to save on
	 * setup/tear-down messages with every invocation of an agent. This
	 * will also help speedup handoffs. This process can be ignored
	 * in a mock agent implementation
	 * 
	 * @param host Click based MAgent host
	 * @return 0 on success, -1 otherwise
	 */
	public int init (InetAddress host);
	
	
	/**
	 * Get the IOFSwitch for this agent
	 * @return ofSwitch
	 */
	public IOFSwitch getSwitch ();
	
	
	/**
	 * Set the IOFSwitch entity corresponding to this agent
	 * 
	 * @param sw the IOFSwitch entity for this agent
	 */
	public void setSwitch (IOFSwitch sw);
	
	
	/**
	 * Remove an SVAP from the AP corresponding to this agent
	 * 
	 * @param staHwAddr The STA's ethernet address
	 */
	public void removeClientSvap (MClient mc);
	
		
	/**
	 * Add an SVAP to the AP corresponding to this agent
	 * 
	 * @param staHwAddr The STA's ethernet address
	 * @param staIpAddr The STA's IP address
	 * @param vapBssid	The STA specific BSSID
	 * @param staEssid	The STA specific SSID
	 */
	public void addClientSvap (MClient mc);
	
	
	/**
	 * Update a virtual access point with possibly new IP, BSSID, or SSID
	 * 
	 * @param staHwAddr The STA's ethernet address
	 * @param staIpAddr The STA's IP address
	 * @param vapBssid The STA specific BSSID
	 * @param staEssid The STA specific SSID
	 */
	public void updateClientSvap(MClient mc);
	
	
	public void sendProbeResponse(MACAddress clientHwAddr, MACAddress bssid, Set<String> ssidLists);
	
	/**
	 * Returns timestamp of last heartbeat from agent
	 * @return Timestamp
	 */
	public long getLastHeard (); 
	
	
	/**
	 * Set the lastHeard timestamp of a client
	 * @param t timestamp to update lastHeard value
	 */
	public void setLastHeard (long t);
	
	
	/**
	 * Set subscriptions
	 * @param subscriptions 
	 * @param t timestamp to update lastHeard value
	 */
	public void setSubscriptions (String subscriptionList);
}
