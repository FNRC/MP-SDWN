package net.floodlightcontroller.sdwn.wirelessmaster;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

import net.floodlightcontroller.util.MACAddress;

/**
 * This class does all the book keeping for sdwn's pool-based
 * state. The master and other components of the code
 * refer to an instance of this class to enforce
 * pool constraints. 
 */
class PoolManager 
{
	
	static public final String GLOBAL_POOL = "global";
	private final byte[] oui = {(byte) 0x00, (byte) 0x1b, (byte) 0xb3};
	private final Map<InetAddress, List<String>> agentToPoolListMap = new ConcurrentHashMap<InetAddress, List<String>>();
	private final Map<String, Set<InetAddress>> poolToAgentSetMap = new ConcurrentHashMap<String, Set<InetAddress>>();
	private final Map<String, Set<String>> poolToSsidListMap = new ConcurrentHashMap<String, Set<String>>();
	private final Map<String, Set<MClient>> poolToClientSetMap = new ConcurrentHashMap<String, Set<MClient>> ();
	private final Map<MClient, String> clientToPoolMap = new ConcurrentHashMap<MClient, String>();
	private int numNetworks = 0;
	
	PoolManager () 
	{
		poolToAgentSetMap.put(GLOBAL_POOL, new HashSet<InetAddress>());
		poolToSsidListMap.put(GLOBAL_POOL, new TreeSet<String>());
		poolToClientSetMap.put(GLOBAL_POOL, new TreeSet<MClient>());
	}
	
	
	/**
	 * Get the list of pools that the agent belongs to.
	 * Note: The list will *not* include the global pool.
	 * 
	 * @param agentInetAddr agent's address
	 * @return immutable list of pools that the agent belongs to
	 */
	List<String> getPoolsForAgent(InetAddress agentInetAddr) 
	{
		if (agentToPoolListMap.containsKey(agentInetAddr))
			return Collections.unmodifiableList(agentToPoolListMap.get(agentInetAddr));
		else
			return Collections.<String>emptyList();
	}
	
	
	/**
	 * Place the agent in an additional pool.
	 *  
	 * @param agentInetAddr agent's address
	 * @param pool the pool to add the agent to
	 * 
	 */
	void addPoolForAgent(InetAddress agentInetAddr, String pool) 
	{
		if (agentToPoolListMap.containsKey(agentInetAddr)) 
		{
			agentToPoolListMap.get(agentInetAddr).add(pool);
		}				
		else 
		{
			List<String> poolList = new ArrayList<String>();
			poolList.add(pool);
			agentToPoolListMap.put(agentInetAddr, poolList);
		}
		
		if (!poolToClientSetMap.containsKey(pool)) 
		{
			poolToAgentSetMap.put(pool, new HashSet<InetAddress>());
			poolToClientSetMap.put(pool, new TreeSet<MClient>());
			poolToSsidListMap.put(pool, new TreeSet<String>());
		}
		
		poolToAgentSetMap.get(GLOBAL_POOL).add(agentInetAddr);
		poolToAgentSetMap.get(pool).add(agentInetAddr);
	}
	
	/**
	 * Get the set of SSIDs that are being
	 * hosted in a pool
	 * 
	 * @param pool 
	 * @return An immutable set of SSIDs
	 */
	Set<String> getSsidListForPool(String pool)
	{
		if (!poolToSsidListMap.containsKey(pool)) 
		{
			return Collections.emptySet();
		}
		return Collections.unmodifiableSet(poolToSsidListMap.get(pool));
	}
	
	
	/**
	 * Add an SSID to a pool. Will return false if
	 * the SSID is already being used within some
	 * other pool.
	 * 
	 * @param pool
	 * @param ssid
	 * @return true if the SSID was added, false otherwise.
	 */
	boolean addNetworkForPool(String pool, String ssid) 
	{
		assert (pool != GLOBAL_POOL);
		/*
		 * First add to the global pool. If this addition
		 * is successful, it follows that the SSID is unique,
		 * and can be added to the specified pool as well.
		 */
		if (poolToSsidListMap.get(GLOBAL_POOL).add(ssid))
		{
			poolToSsidListMap.get(pool).add(ssid);
			numNetworks++;
			return true;
		}
		
		return false;
	}
	
	
	/**
	 * Removes a network from a pool. Returns false
	 * if the network name isn't registered with the pool
	 * 
	 * @param pool
	 * @param ssid
	 * @return true if the ssid could be removed. False otherwise.
	 */
	boolean removeNetworkFromPool(String pool, String ssid) 
	{
		assert (pool != GLOBAL_POOL);
		/*
		 * First remove from local pool. If that succeeds, remove
		 * from the global pool as well.
		 */
		if (poolToSsidListMap.get(pool).remove(ssid)) 
		{
			poolToSsidListMap.get(GLOBAL_POOL).remove(ssid);
			numNetworks--;
			return true;
		}
		
		return false;
	}
	
	
	/**
	 * Generates a BSSID for a client. 
	 *  
	 * @param clientHwAddress
	 * @return BSSID for the client
	 */
	MACAddress generateBssidForClient(MACAddress clientHwAddress)
	{
		// XXX: This could be done more intelligently someday
		byte[] bssidBytes = clientHwAddress.toBytes();
		bssidBytes[0] = oui[0];
		bssidBytes[1] = oui[1];
		bssidBytes[2] = oui[2];
		final MACAddress bssid = MACAddress.valueOf(bssidBytes);
		
		return bssid;
	}
	
	
	/**
	 * Returns the total number of unique SSIDs that have been
	 * registered across all pools.
	 * 
	 * @return
	 */
	int getNumNetworks() 
	{
		return numNetworks;
	}
	
	
	/**
	 * Place a client in a particular pool.
	 *  
	 * @param client
	 * @param pool
	 */
	void mapClientToPool(MClient client, String pool) 
	{
		assert (pool != null);
		assert (pool != GLOBAL_POOL);
						
		String currentPool = clientToPoolMap.put(client, pool);
				
		if (currentPool != null) 
		{
			poolToClientSetMap.get(currentPool).remove(client);
		}
		
		poolToClientSetMap.get(GLOBAL_POOL).add(client);
		poolToClientSetMap.get(pool).add(client);
	}
	
	
	/**
	 * Remove a client from a particular pool
	 * 
	 * @param client
	 */
	void removeClientPoolMapping(MClient client)
	{
		String currentPool = clientToPoolMap.get(client);
		
		if (currentPool != null) 
		{
			poolToClientSetMap.get(currentPool).remove(client);
			clientToPoolMap.remove(client);
		}
	}
	
	
	/**
	 * Get the set of clients that have connected to a
	 * particular pool
	 * 
	 * @param pool
	 * @return Immutable set of MClient instances in that pool
	 */
	Set<MClient> getClientsFromPool(String pool) 
	{
		return Collections.unmodifiableSet(poolToClientSetMap.get(pool));
	}
	
	
	/**
	 * Get the pool that the client is connected to 
	 * 
	 * @param client
	 * @return
	 */
	String getPoolForClient(MClient client) 
	{
		return clientToPoolMap.get(client);
	}
	
	Set<InetAddress> getAgentAddrsForPool(String pool)
	{
		Set<InetAddress> ret = poolToAgentSetMap.get(pool);
		
		return (ret == null) ? Collections.<InetAddress>emptySet() : ret; 
	}
}