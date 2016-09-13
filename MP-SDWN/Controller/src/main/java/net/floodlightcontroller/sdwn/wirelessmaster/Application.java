package net.floodlightcontroller.sdwn.wirelessmaster;

import java.net.InetAddress;
import java.util.Map;
import java.util.Set;

import net.floodlightcontroller.sdwn.wirelessmaster.IApplicationInterface;
import net.floodlightcontroller.sdwn.wirelessmaster.NotificationCallback;
import net.floodlightcontroller.sdwn.wirelessmaster.MClient;
import net.floodlightcontroller.sdwn.wirelessmaster.EventSubscription;
import net.floodlightcontroller.util.MACAddress;


/**
 * Base class for all sdwn applications. They are
 * expected to run as a thread provided by the master. 
 */
public abstract class Application implements Runnable 
{

	private IApplicationInterface ApplicationInterface;
	private String pool;
	
	
	/**
	 * Set the WirelessMaster to use
	 */
	final void setOdinInterface (IApplicationInterface wm) 
	{
		ApplicationInterface = wm;
	}
	
	
	/**
	 * Sets the pool to use for the application
	 * @param pool
	 */
	final void setPool (String pool) 
	{
		this.pool = pool;
	}
	
	
	/**
	 * Needed to wrap Applications into a thread, and is
	 * implemented by the specific application
	 */
	public abstract void run();

	
	/**
	 * VAP-Handoff a client to a new AP. This operation is idempotent.
	 * 
	 * @param newApIpAddr IPv4 address of new access point
	 * @param hwAddrSta Ethernet address of STA to be handed off
	 */
	protected final void handoffClientToAp (MACAddress staHwAddr, InetAddress newApIpAddr) 
	{
		ApplicationInterface.handoffClientToAp(pool, staHwAddr, newApIpAddr);
	}

	
	/**
	 * Get the list of clients currently registered with sdwn
	 * 
	 * @return a map of OdinClient objects keyed by HW Addresses
	 */
	protected final Set<MClient> getClients () 
	{
		return ApplicationInterface.getClients(pool);		
	}
	
	
	/**
	 * Get the MClient type from the client's MACAddress
	 * 
	 * @return a MClient instance corresponding to clientHwAddress
	 */
	protected final MClient getClientFromHwAddress (MACAddress clientHwAddress) 
	{
		return ApplicationInterface.getClientFromHwAddress(pool, clientHwAddress);
	}
	
	
	/**
	 * Retreive RxStats from the agent
	 * 
	 * @param agentAddr InetAddress of the agent
	 * 
	 * @return Key-Value entries of each recorded statistic for each client 
	 */
	protected final Map<MACAddress, Map<String, String>> getRxStatsFromAgent (InetAddress agentAddr) 
	{
		return ApplicationInterface.getRxStatsFromAgent(pool, agentAddr);
	}
	
	/**
	 * Get a list of M agents from the agent tracker
	 * @return a map of MAgent objects keyed by Ipv4 addresses
	 */
	protected final Set<InetAddress> getAgents () 
	{
		return ApplicationInterface.getAgentAddrs(pool);
	}
	
	
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
	protected final long registerSubscription (EventSubscription oes, NotificationCallback cb)
	{
		return ApplicationInterface.registerSubscription(pool, oes, cb);
	}
	
	
	/**
	 * Remove a subscription from the list
	 * 
	 * @param id subscription id to remove
	 * @return
	 */
	protected final void unregisterSubscription (long id) 
	{
		ApplicationInterface.unregisterSubscription(pool, id);
	}
	
	
	/**
	 * Add an SSID to the SDWN network.
	 * 
	 * @param networkName
	 * @return true if the network could be added, false otherwise
	 */
	protected final boolean addNetwork (String ssid) 
	{
		return ApplicationInterface.addNetwork(pool, ssid);
	}
	
	
	/**
	 * Remove an SSID from the SDWN network.
	 * 
	 * @param networkName
	 * @return true if the network could be removed, false otherwise
	 */
	protected final boolean removeNetwork (String ssid) 
	{
		return ApplicationInterface.removeNetwork(pool, ssid);
	}
}
