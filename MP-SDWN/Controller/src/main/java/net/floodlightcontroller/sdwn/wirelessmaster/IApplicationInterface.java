package net.floodlightcontroller.sdwn.wirelessmaster;

import java.net.InetAddress;
import java.util.Map;
import java.util.Set;

import net.floodlightcontroller.sdwn.wirelessmaster.MClient;
import net.floodlightcontroller.util.MACAddress;

interface IApplicationInterface 
{

	/**
	 * VAP-Handoff a client to a new AP. This operation is idempotent.
	 * 
	 * @param newApIpAddr IPv4 address of new access point
	 * @param hwAddrSta Ethernet address of STA to be handed off
	 */
	void handoffClientToAp (String pool, MACAddress staHwAddr, InetAddress newApIpAddr);

	
	/**
	 * Get the list of clients currently registered with sdwn
	 * 
	 * @return a map of OdinClient objects keyed by HW Addresses
	 */
	Set<MClient> getClients (String pool);
	
	
	/**
	 * Get the MClient type from the client's MACAddress
	 * 
	 * @param pool that the invoking application corresponds to
	 * @return a MClient instance corresponding to clientHwAddress
	 */
	MClient getClientFromHwAddress (String pool, MACAddress clientHwAddress);
	
	Map<MACAddress, Map<String, String>> getRxStatsFromAgent (String pool, InetAddress agentAddr);
	
	/**
	 * Get a list of SDWN agents from the agent tracker
	 * @return a map of MAgent objects keyed by Ipv4 addresses
	 */
	Set<InetAddress> getAgentAddrs (String pool);
	
	
	/**
	 * Add a subscription for a particular event defined by oes. cb is
	 * defines the application specified callback to be invoked during
	 * notification. If the application plans to delete the subscription,
	 * later, the onus is upon it to keep track of the subscription
	 * id for removal later.
	 * 
	 * @param oes the susbcription
	 * @param cb the callback
	 */
	long registerSubscription (String pool, EventSubscription oes, NotificationCallback cb);
	
	
	/**
	 * Remove a subscription from the list
	 * 
	 * @param id subscription id to remove
	 * @return
	 */
	void unregisterSubscription (String pool, long id);
	
	
	/**
	 * Add an SSID to the SDWN network.
	 * 
	 * @param networkName
	 * @return true if the network could be added, false otherwise
	 */
	boolean addNetwork (String pool, String ssid);
	
	
	/**
	 * Remove an SSID from the SDWN network.
	 * 
	 * @param networkName
	 * @return true if the network could be removed, false otherwise
	 */
	boolean removeNetwork (String pool, String ssid);
}
