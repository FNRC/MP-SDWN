package net.floodlightcontroller.sdwn.wirelessmaster;

import java.net.InetAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import net.floodlightcontroller.sdwn.wirelessmaster.MClient;
import net.floodlightcontroller.util.MACAddress;

class ClientManager 
{
	private final Map<MACAddress, MClient> MClientMap = new ConcurrentHashMap<MACAddress, MClient> ();

	
	/**
	 * Add a client to the client tracker
	 * 
	 * @param hwAddress Client's hw address
	 * @param ipv4Address Client's IPv4 address
	 * @param vapBssid Client specific VAP bssid
	 * @param vapEssid Client specific VAP essid
	 */
	protected void addClient (final MACAddress clientHwAddress, final InetAddress ipv4Address, final Svap svap) 
	{
		MClientMap.put(clientHwAddress, new MClient (clientHwAddress, ipv4Address, svap));
	}
	
	
	/**
	 * Add a client to the client tracker
	 * 
	 * @param hwAddress Client's hw address
	 * @param ipv4Address Client's IPv4 address
	 * @param vapBssid Client specific VAP bssid
	 * @param vapEssid Client specific VAP essid
	 */
	protected void addClient (final MClient mc) 
	{
		MClientMap.put(mc.getMacAddress(), mc);
	}
	
	
	/**
	 * Removes a client from the tracker
	 * 
	 * @param hwAddress Client's hw address
	 */
	protected void removeClient (final MACAddress clientHwAddress) 
	{
		MClientMap.remove(clientHwAddress);
	}
	
	
	/**
	 * Get a client by hw address
	 */
	protected MClient getClient (final MACAddress clientHwAddress) 
	{
		return MClientMap.get(clientHwAddress);
	}
	
	
	/**
	 * Get the client Map from the manager
	 * @return client map
	 */
	protected Map<MACAddress, MClient> getClients () 
	{
		return MClientMap;
	}
}
