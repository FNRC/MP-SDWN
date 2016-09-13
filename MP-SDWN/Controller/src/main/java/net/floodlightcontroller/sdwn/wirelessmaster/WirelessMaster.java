package net.floodlightcontroller.sdwn.wirelessmaster;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.TreeSet;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.*;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
//import org.openflow.protocol.OFMessage;
//import org.openflow.protocol.OFType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.DHCP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.util.MACAddress;


/**
 * WirelessMaster implementation. Exposes interfaces to Applications,
 * and keeps track of agents and clients in the system.
 * 
 * @author Lalith Suresh <suresh.lalith@gmail.com>
 *
 */
public class WirelessMaster implements IFloodlightModule, IOFSwitchListener, IApplicationInterface, IOFMessageListener, IFloodlightService 
{
	protected static Logger log = LoggerFactory.getLogger(WirelessMaster.class);
	protected IRestApiService restApi;

	private IFloodlightProviderService floodlightProvider;
	private ScheduledExecutorService executor;
	
	private final AgentManager agentManager;
	private final ClientManager clientManager;	
	private final SvapManager svapManager;
	private final PoolManager poolManager;
	protected IOFSwitchService switchService;
	private long subscriptionId = 0;
	private String subscriptionList = "";
	private int idlesvapTimeout = 60; // Seconds
	
	private final ConcurrentMap<Long, SubscriptionCallbackTuple> subscriptions = new ConcurrentHashMap<Long, SubscriptionCallbackTuple>();

	// some defaults
	static private final String DEFAULT_POOL_FILE = "poolfile"; 
	static private final String DEFAULT_CLIENT_LIST_FILE = "sdwn_client_list";  
	static private final int DEFAULT_PORT = 2819;
	
	public WirelessMaster()
	{
		clientManager = new ClientManager();
		svapManager = new SvapManager();
		poolManager = new PoolManager();
		agentManager = new AgentManager(clientManager, poolManager);
	}
	
	public WirelessMaster(AgentManager agentManager, ClientManager clientManager, SvapManager svapManager, PoolManager poolManager)
	{
		this.agentManager = agentManager;
		this.clientManager = clientManager;
		this.svapManager = svapManager;
		this.poolManager = poolManager;
	}
	
	
	//********* MAgent->Master protocol handlers *********//
	
	/**
	 * Handle a ping from an agent
	 * 
	 * @param InetAddress of the agent
	 */
	synchronized void receivePing (final InetAddress MAgentAddr) 
	{
		if (agentManager.receivePing(MAgentAddr)) 
		{
			// if the above leads to a new agent being
			// tracked, push the current subscription list
			// to it.
			IMAgent agent = agentManager.getAgent(MAgentAddr);
			pushSubscriptionListToAgent(agent);

			// Reclaim idle svaps and also attach flows to svaps
			for (MClient client: agent.getSvapsLocal()) 
			{
				executor.schedule(new IdlesvapReclaimTask(client), idlesvapTimeout, TimeUnit.SECONDS);
				
				// Assign flow tables
				if (!client.getIpAddress().getHostAddress().equals("0.0.0.0")) 
				{
					
					// Obtain reference to client entity from clientManager, because agent.getSvapsLocal()
					// returns a separate copy of the client objects.
					MClient trackedClient = clientManager.getClients().get(client.getMacAddress());
					Svap svap = trackedClient.getSvap();
					assert (svap != null);
				//	svap.setOFMessageList(svapManager.getDefaultOFModList(client.getIpAddress()));
					
					// Push flow messages associated with the client
					for(IMAgent ma:svap.getAgents())
					{
						//ma.getSwitch().write(svap.getOFMessageList(), null);
						svapManager.getDefaultOFModList(ma.getSwitch(),client.getIpAddress());
        			}
				}
			}
		}
		else 
		{
			updateAgentLastHeard (MAgentAddr);
		}
	}
	
	/**
	 * Handle a probe message from an agent, triggered
	 * by a particular client.
	 * 
	 * @param MAgentAddr InetAddress of agent
	 * @param clientHwAddress MAC address of client that performed probe scan
	 */
	synchronized void receiveProbe (final InetAddress MAgentAddr, final MACAddress clientHwAddress, String ssid) 
	{
		
		if (MAgentAddr == null
	    	|| clientHwAddress == null
	    	|| clientHwAddress.isBroadcast()
	    	|| clientHwAddress.isMulticast()
	    	|| agentManager.isTracked(MAgentAddr) == false
	    	|| poolManager.getNumNetworks() == 0) 
		{
			return;
		}
		
		System.out.println("receive probe request from client "+clientHwAddress+" through agent "+MAgentAddr.getHostAddress().toString());			

		updateAgentLastHeard(MAgentAddr);
		
		/*
		 * If clients perform an active scan, generate
		 * probe responses without spawning svaps
		 */
		if (ssid.equals("")) 
		{
			// we just send probe responsesoc.getSvap().getAgent()
			IMAgent agent = agentManager.getAgent(MAgentAddr);
			MACAddress bssid = poolManager.generateBssidForClient(clientHwAddress);		
			// FIXME: Sub-optimal. We'll end up generating redundant probe requests
			Set<String> ssidSet = new TreeSet<String> ();
			for (String pool: poolManager.getPoolsForAgent(MAgentAddr)) 
			{
				if (pool.equals(PoolManager.GLOBAL_POOL))
					continue;
				ssidSet.addAll(poolManager.getSsidListForPool(pool));
			}
			System.out.print("probe response from:"+agent.getIpAddress().getHostAddress().toString()+" to client "+clientHwAddress+" with virtual BSSID and SSID:"+bssid+" and ");	
			Iterator<String> it=ssidSet.iterator();
			while(it.hasNext())
				System.out.println(it.next());
			executor.execute(new MAgentSendProbeResponseRunnable(agent, clientHwAddress, bssid, ssidSet));			
			return;
		}
				
		/*
		 * Client is scanning for a particular SSID. Verify
		 * which pool is hosting the SSID, and assign
		 * an svap into that pool
		 */
		for (String pool: poolManager.getPoolsForAgent(MAgentAddr)) 
		{
			if (poolManager.getSsidListForPool(pool).contains(ssid)) 
			{
				MClient mc = clientManager.getClient(clientHwAddress);
					    	
		    	// Hearing from this client for the first time
		    	if (mc == null) 
		    	{		    		
					List<String> ssidList = new ArrayList<String> ();
					Set<IMAgent> agents = new HashSet<IMAgent> ();
					ssidList.addAll(poolManager.getSsidListForPool(pool));
					
					Svap svap = new Svap (poolManager.generateBssidForClient(clientHwAddress), ssidList);
					svap.setAgents(agents);
					try 
					{
						mc = new MClient(clientHwAddress, InetAddress.getByName("0.0.0.0"), svap);
					} 
					catch (UnknownHostException e) 
					{
						e.printStackTrace();
					}
		    		clientManager.addClient(mc);
		    	}
		    	
		    	Svap svap = mc.getSvap();
		    	assert (svap != null);

		    	if (svap.getAgents() == null || !svap.IsInSet(MAgentAddr)) 
		    	{
					// client is connecting for the
					// first time, had explicitly
					// disconnected, or knocked
					// out at as a result of an agent
					// failure.
					
					// Use global pool for first time connections
					//handoffClientToApInternal(PoolManager.GLOBAL_POOL, clientHwAddress, odinAgentAddr);
		    		IMAgent newAgent =agentManager.getAgent(MAgentAddr);
				//if(svap.getAgent()==null)
		    		log.info ("Client: " + clientHwAddress + " connecting for first time. Assigning to: " + newAgent.getIpAddress().getHostAddress().toString());
				
				    //newAgent.getSwitch().write(svap.getOFMessageList(), null);
				    
	
		    		newAgent.addClientSvap(mc);
		    		log.info("addsvap "+svap.getBssid()+":"+svap.getSsids()+" for client "+clientHwAddress+" on the agent " +newAgent.getIpAddress().getHostAddress().toString());
		    		System.out.println("Add the Agent:"+newAgent.getIpAddress()+" to the svap's Set of client "+mc.getMacAddress());
		    		svap.getAgents().add(newAgent);
		    		executor.schedule(new IdlesvapReclaimTask (mc), idlesvapTimeout, TimeUnit.SECONDS);
		    	}
			
		    	else
		    	{
		    		Set<IMAgent> agents=svap.getAgents();
		    		Iterator<IMAgent> it=agents.iterator();
		    		while(it.hasNext())
		    		{
		    			InetAddress currentApIpAddress = it.next().getIpAddress();
		    			if (currentApIpAddress.getHostAddress().equals(MAgentAddr.getHostAddress())) 
		    			{
		    				log.info ("Client " + clientHwAddress + " is already associated with AP " + MAgentAddr);
		    			}	
		    		}
		    	}
		    	poolManager.mapClientToPool(mc, pool);
				
		    	return;
			}
		}
	}
	
	/**
	 * Handle an event publication from an agent
	 * 
	 * @param clientHwAddress client which triggered the event
	 * @param odinAgentAddr agent at which the event was triggered
	 * @param subscriptionIds list of subscription Ids that the event matches
	 */
	synchronized void receivePublish (final MACAddress clientHwAddress, final InetAddress MAgentAddr, final Map<Long, Long> subscriptionIds) 
	{

		// The check for null clientHwAddress might go away
		// in the future if we end up having events
		// that are not related to clients at all.
		if (clientHwAddress == null || MAgentAddr == null || subscriptionIds == null)
			return;
		
		IMAgent ma = agentManager.getAgent(MAgentAddr);
		
		// This should never happen!
		if (ma == null)
			return;

		// Update last-heard for failure detection
		ma.setLastHeard(System.currentTimeMillis());
		
		for (Entry<Long, Long> entry: subscriptionIds.entrySet()) 
		{
			SubscriptionCallbackTuple tup = subscriptions.get(entry.getKey());
			
			/* This might occur as a race condition when the master
			 * has cleared all subscriptions, but hasn't notified
			 * the agent about it yet.
			 */
			if (tup == null)
				continue;


			NotificationCallbackContext cntx = new NotificationCallbackContext(clientHwAddress, ma, entry.getValue());
			
			tup.cb.exec(tup.oes, cntx);
		}
	}

	
	/**
	 * VAP-Handoff a client to a new AP. This operation is idempotent.
	 * 
	 * @param newApIpAddr IPv4 address of new access point
	 * @param hwAddrSta Ethernet address of STA to be handed off
	 */
	private void handoffClientToApInternal (String pool, final MACAddress clientHwAddr, final InetAddress newApIpAddr)
	{
		
		// As an optimisation, we probably need to get the accessing done first,
		// prime both nodes, and complete a handoff. 
		
		if (pool == null || clientHwAddr == null || newApIpAddr == null) 
		{
			log.error("null argument in handoffClientToAp(): pool:" + pool + "clientHwAddr: " + clientHwAddr + " newApIpAddr: " + newApIpAddr);
			return;
		}
		
		synchronized (this) 
		{
		
			IMAgent newAgent = agentManager.getAgent(newApIpAddr);
			
			// If new agent doesn't exist, ignore request
			if (newAgent == null)
			{
				log.error("Handoff request ignored: MAgent " + newApIpAddr + " doesn't exist");
				return;
			}
			
			MClient client = clientManager.getClient(clientHwAddr);
			
			// Ignore request if we don't know the client
			if (client == null) 
			{
				log.error("Handoff request ignored: MClient " + clientHwAddr + " doesn't exist");
				return;
			}
			
			Svap svap = client.getSvap();
			
			assert (svap != null);
			
			/* If the client is connecting for the first time, then it
			 * doesn't have a VAP associated with it already
			 */
			if (svap.getAgents() == null || !svap.IsInSet(newApIpAddr))
			{
				log.info ("Client: " + clientHwAddr + " connecting for first time. Assigning to: " + newAgent.getIpAddress().getHostAddress().toString());
	
				//newAgent.getSwitch().write(svap.getOFMessageList(), null);
				svapManager.getDefaultOFModList(newAgent.getSwitch(),newAgent.getIpAddress());
				newAgent.addClientSvap(client);
				log.info("addsvap "+svap.getBssid()+":"+svap.getSsids()+" for client "+clientHwAddr+" on the agent " +newAgent.getIpAddress().getHostAddress().toString());
				svap.getAgents().add(newAgent);
				executor.schedule(new IdlesvapReclaimTask (client), idlesvapTimeout, TimeUnit.SECONDS);
				return;
			}
			
			/* If the client is already associated with AP-newIpAddr, we ignore
			 * the request.
			 */
			for(IMAgent ag:svap.getAgents())
			{
				InetAddress ApIpAddress = ag.getIpAddress();
				if (ApIpAddress.getHostAddress().equals(newApIpAddr.getHostAddress())) 
				{
					log.info ("Client " + clientHwAddr + " is already associated with AP " + newApIpAddr);
					return;
				}
			}
			
			/* Verify permissions.
			 * 
			 * - newAP and oldAP should both fall within the same pool.
			 * - client should be within the same pool as the two APs.
			 * - invoking application should be operating on the same pools
			 *  
			 * By design, this prevents handoffs within the scope of the
			 * GLOBAL_POOL since that would violate a lot of invariants
			 * in the rest of the system.
			 */
			
			String clientPool = poolManager.getPoolForClient(client);
			
			if (clientPool == null || !clientPool.equals(pool)) 
			{
				log.error ("Cannot handoff client '" + client.getMacAddress() + "' from " + clientPool + " domain when in domain: '" + pool + "'");
			}
			
			
			InetAddress currentIpAddress=null;
			for(IMAgent ag:svap.getAgents())
			{
				InetAddress currentApIpAddress=ag.getIpAddress();
				if (! (poolManager.getPoolsForAgent(newApIpAddr).contains(pool)
					&& poolManager.getPoolsForAgent(currentApIpAddress).contains(pool)) )
				{
					log.info ("Agents " + newApIpAddr + " and " + currentApIpAddress + " are not in the same pool: " + pool);
					continue;
				}
				else
				{
					currentIpAddress=currentApIpAddress;
					break;
				}
			}
			
			//newAgent.getSwitch().write(svap.getOFMessageList(), null);
			svapManager.getDefaultOFModList(newAgent.getSwitch(),newAgent.getIpAddress());
			/* Client is with another AP. We remove the VAP from
			 * the current AP of the client, and spawn it on the new one.
			 * We split the add and remove VAP operations across two threads
			 * to make it faster. Note that there is a temporary inconsistent 
			 * state between setting the agent for the client and it actually 
			 * being reflected in the network 
			 */
			svap.getAgents().add(newAgent);
			executor.execute(new MAgentsvapAddRunnable(newAgent, client));
			executor.execute(new MAgentsvapRemoveRunnable(agentManager.getAgent(currentIpAddress), client));
		}
	}
	
	//********* SDWN methods to be used by applications (from IOdinApplicationInterface) **********//
	
	/**
	 * VAP-Handoff a client to a new AP. This operation is idempotent.
	 * 
	 * @param newApIpAddr IPv4 address of new access point
	 * @param hwAddrSta Ethernet address of STA to be handed off
	 */
	@Override
	public void handoffClientToAp (String pool, final MACAddress clientHwAddr, final InetAddress newApIpAddr)
	{
		handoffClientToApInternal(pool, clientHwAddr, newApIpAddr);
	}
	
	
	/**
	 * Get the list of clients currently registered with SDWN
	 * 
	 * @return a map of MClient objects keyed by HW Addresses
	 */
	@Override
	public Set<MClient> getClients (String pool) 
	{
		return poolManager.getClientsFromPool(pool);
	}
	
	
	/**
	 * Get the MClient type from the client's MACAddress
	 * 
	 * @param pool that the invoking application corresponds to
	 * @param clientHwAddress MACAddress of the client
	 * @return a MClient instance corresponding to clientHwAddress
	 */
	@Override
	public MClient getClientFromHwAddress (String pool, MACAddress clientHwAddress) 
	{
		MClient client = clientManager.getClient(clientHwAddress);
		return (client != null && poolManager.getPoolForClient(client).equals(pool)) ? client : null;
	}
	
	
	/**
	 * Retreive RxStats from the agent
	 * 
	 * @param pool that the invoking application corresponds to
	 * @param agentAddr InetAddress of the agent
	 * 
	 * @return Key-Value entries of each recorded statistic for each client 
	 */
	@Override
	public Map<MACAddress, Map<String, String>> getRxStatsFromAgent (String pool, InetAddress agentAddr) 
	{
		return agentManager.getAgent(agentAddr).getRxStats();		
	}
	
	
	/**
	 * Get a list of M agents from the agent tracker
	 * @return a map of OdinAgent objects keyed by Ipv4 addresses
	 */
	@Override
	public Set<InetAddress> getAgentAddrs (String pool)
	{
		return poolManager.getAgentAddrsForPool(pool);
	}
	
	
	/**
	 * Add a subscription for a particular event defined by oes. cb
	 * defines the application specified callback to be invoked during
	 * notification. If the application plans to delete the subscription,
	 * later, the onus is upon it to keep track of the subscription
	 * id for removal later.
	 * 
	 * @param oes the susbcription
	 * @param cb the callback
	 */
	@Override
	public synchronized long registerSubscription (String pool, final EventSubscription oes, final NotificationCallback cb) 
	{
		// FIXME: Need to calculate subscriptions per pool
		assert (oes != null);
		assert (cb != null);
		SubscriptionCallbackTuple tup = new SubscriptionCallbackTuple();
		tup.oes = oes;
		tup.cb = cb;
		subscriptionId++;
		subscriptions.put(subscriptionId, tup);
		
		/**
		 * Update the subscription list, and push to all agents
		 * TODO: This is a common subsriptOdinMobilityManagerion string being
		 * sent to all agents. Replace this with per-agent
		 * subscriptions.
		 */
		subscriptionList = "";
		int count = 0;
		for (Entry<Long, SubscriptionCallbackTuple> entry: subscriptions.entrySet()) 
		{
			count++;
			final String addr = entry.getValue().oes.getClient();
			subscriptionList = subscriptionList + 
								entry.getKey() + " " + 
								(addr.equals("*") ? MACAddress.valueOf("00:00:00:00:00:00") : addr)  + " " +
								entry.getValue().oes.getStatistic() + " " +
								entry.getValue().oes.getRelation().ordinal() + " " +
								entry.getValue().oes.getValue() + " ";
		}

		subscriptionList = String.valueOf(count) + " " + subscriptionList;

		/**
		 * Should probably have threads to do this
		 */
		for (InetAddress agentAddr : poolManager.getAgentAddrsForPool(pool)) 
		{
			pushSubscriptionListToAgent(agentManager.getAgent(agentAddr));
		}
		
		return subscriptionId;
	}
	
	
	/**
	 * Remove a subscription from the list
	 * 
	 * @param id subscription id to remove
	 * @return
	 */
	@Override
	public synchronized void unregisterSubscription (String pool, final long id) 
	{
		// FIXME: Need to calculate subscriptions per pool
		subscriptions.remove(id);
		
		subscriptionList = "";
		int count = 0;
		for (Entry<Long, SubscriptionCallbackTuple> entry: subscriptions.entrySet()) 
		{
			count++;
			final String addr = entry.getValue().oes.getClient();
			subscriptionList = subscriptionList + 
								entry.getKey() + " " + 
								(addr.equals("*") ? MACAddress.valueOf("00:00:00:00:00:00") : addr)  + " " +
								entry.getValue().oes.getStatistic() + " " +
								entry.getValue().oes.getRelation().ordinal() + " " +
								entry.getValue().oes.getValue() + " ";
		}

		subscriptionList = String.valueOf(count) + " " + subscriptionList;

		/**
		 * Should probably have threads to do this
		 */
		for (InetAddress agentAddr : poolManager.getAgentAddrsForPool(pool)) 
		{
			pushSubscriptionListToAgent(agentManager.getAgent(agentAddr));
		}
	}
	

	/**
	 * Add an SSID to the SDWN network.
	 * 
	 * @param networkName
	 * @return true if the network could be added, false otherwise
	 */
	@Override
	public synchronized boolean addNetwork (String pool, String ssid) 
	{
		if (poolManager.addNetworkForPool(pool, ssid)) 
		{	
			for(MClient mc: poolManager.getClientsFromPool(pool)) 
			{
				Svap svap = mc.getSvap();
				assert (svap != null);
				svap.getSsids().add(ssid);
				
				Set<IMAgent> agents = svap.getAgents();
				
				if (agents != null) 
				{
					// FIXME: Ugly API
					for(IMAgent agent:agents)
					    agent.updateClientSvap(mc);
				}
			}		
			return true;
		}
		return false;
	}
	
	
	/**
	 * Remove an SSID from the SDWN network.
	 * 
	 * @param networkName
	 * @return true if the network could be removed, false otherwise
	 */
	@Override
	public synchronized boolean removeNetwork (String pool, String ssid) 
	{
		if (poolManager.removeNetworkFromPool(pool, ssid))
		{
			// need to update all existing svaps in the network as well
			
			for (MClient mc: poolManager.getClientsFromPool(pool)) 
			{
				
				Svap svap = mc.getSvap();
				assert (svap != null);
				svap.getSsids().remove(ssid);
				
				Set<IMAgent> agents = svap.getAgents();
				
				if (agents != null) 
				{
					// FIXME: Ugly API
					for(IMAgent agent:agents)
					     agent.updateClientSvap(mc);
				}
			}
			
			return true;
		}
			
		return false;
	}
	
	
	//********* from IFloodlightModule **********//
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService>> l =
	        new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
        l.add(IRestApiService.class);
        l.add(IOFSwitchService.class);
        l.add(IThreadPoolService.class);
		return l;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() 
	{
		Map<Class<? extends IFloodlightService>,
        IFloodlightService> m =
        new HashMap<Class<? extends IFloodlightService>,
        IFloodlightService>();
        m.put(WirelessMaster.class, this);
        return m;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		IThreadPoolService tp = context.getServiceImpl(IThreadPoolService.class);
		executor = tp.getScheduledExecutor();
	}
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
	@Override
	public void startUp(FloodlightModuleContext context) 
	{		
		switchService.addOFSwitchListener(this);
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		restApi.addRestletRoutable(new WirelessMasterWebRoutable());
		
		agentManager.setFloodlightProvider (floodlightProvider,switchService);
		
		// read config options
        Map<String, String> configOptions = context.getConfigParams(this);
        
        
        // List of trusted agents
        String agentAuthListFile = DEFAULT_POOL_FILE;
        String agentAuthListFileConfig = configOptions.get("poolFile");
        
        if (agentAuthListFileConfig != null) 
        {
        	agentAuthListFile = agentAuthListFileConfig; 
        }
        
        List<Application> applicationList = new ArrayList<Application>();
       	try 
       	{
			BufferedReader br = new BufferedReader (new FileReader(agentAuthListFile));
			
			String strLine;
			
			/* Each line has the following format:
			 * 
			 * IPAddr-of-agent  pool1 pool2 pool3 ...
			 */
			while ((strLine = br.readLine()) != null) 
			{
				if (strLine.startsWith("#")) // comment
					continue;
				
				if (strLine.length() == 0) // blank line
					continue;
				
				// NAME
				String [] fields = strLine.split(" "); 
				if (!fields[0].equals("NAME")) 
				{
					log.error("Missing NAME field " + fields[0]);
					log.error("Offending line: " + strLine);
					System.exit(1);
				}
				
				if (fields.length != 2) 
				{
					log.error("A NAME field should specify a single string as a pool name");
					log.error("Offending line: " + strLine);
					System.exit(1);
				}

				String poolName = fields[1];
				System.out.println("pool:"+poolName);				
				// NODES
				strLine = br.readLine();
				
				if (strLine == null) 
				{
					log.error("Unexpected EOF after NAME field for pool: " + poolName);
					System.exit(1);
				}
				
				fields = strLine.split(" ");
				
				if (!fields[0].equals("NODES"))
				{
					log.error("A NAME field should be followed by a NODES field");
					log.error("Offoc.getSvap().getAgent()ending line: " + strLine);
					System.exit(1);
				}
				
				if(fields.length == 1) 
				{				
					log.error("A pooc.getSvap().getAgent()ol must have at least one node defined for it");
					log.error("Offending line: " + strLine);
					System.exit(1);
				}
				
				for (int i = 1; i < fields.length; i++) 
				{
					poolManager.addPoolForAgent(InetAddress.getByName(fields[i]), poolName);
					System.out.println(fields[i]);
				}
				
				// NETWORKS
				strLine = br.readLine();
				
				if (strLine == null) 
				{
					log.error("Unexpected EOF after NODES field for pool: " + poolName);
					System.exit(1);
				}

				fields = strLine.split(" ");
				
				if (!fields[0].equals("NETWORKS")) 
				{
					log.error("A NODES field should be followed by a NETWORKS field");
					log.error("Offending line: " + strLine);
					System.exit(1);
				}
				
				for (int i = 1; i < fields.length; i++)
				{
					poolManager.addNetworkForPool(poolName, fields[i]);
					System.out.println(fields[i]);					
				}
				
				// APPLICATIONS
				strLine = br.readLine();
				
				if (strLine == null) 
				{
					log.error("Unexpected EOF after NETWORKS field for pool: " + poolName);
					System.exit(1);
				}

				fields = strLine.split(" ");
				
				if (!fields[0].equals("APPLICATIONS")) 
				{
					log.error("A NETWORKS field should be followed by an APPLICATIONS field");
					log.error("Offending line: " + strLine);
					System.exit(1);
				}
				
				for (int i = 1; i < fields.length; i++) 
				{
					Application appInstance = (Application) Class.forName(fields[i]).newInstance();
					appInstance.setOdinInterface(this);
					appInstance.setPool(poolName);
					applicationList.add(appInstance);
				}
			}
			
      br.close();

		} 
       	catch (FileNotFoundException e1) 
       	{
			log.error("Agent authentication list (config option poolFile) not supplied. Terminating.");
			System.exit(1);
		} 
       	catch (IOException e) 
       	{
			e.printStackTrace();
			System.exit(1);
		} 
       	catch (InstantiationException e) 
       	{
			e.printStackTrace();
		} 
       	catch (IllegalAccessException e) 
       	{			
			e.printStackTrace();
		}
       	catch (ClassNotFoundException e) 
       	{
			e.printStackTrace();
		}

        // Static client - svap assignments
        String clientListFile = DEFAULT_CLIENT_LIST_FILE;
        String clientListFileConfig = configOptions.get("clientList");
        
        if (clientListFileConfig != null) 
        {
            clientListFile = clientListFileConfig;
        }
        
        try 
        {
			BufferedReader br = new BufferedReader (new FileReader(clientListFile));
			
			String strLine;
			
			while ((strLine = br.readLine()) != null) 
			{
				String [] fields = strLine.split(" ");
				
				MACAddress hwAddress = MACAddress.valueOf(fields[0]);
				InetAddress ipaddr = InetAddress.getByName(fields[1]);
				
				ArrayList<String> ssidList = new ArrayList<String> ();
				ssidList.add(fields[3]); // FIXME: assumes a single ssid
				Svap svap = new Svap(MACAddress.valueOf(fields[2]), ssidList);

				log.info("Adding client: " + fields[0] + " " + fields[1] + " " +fields[2] + " " +fields[3]);
				clientManager.addClient(hwAddress, ipaddr, svap);
				System.out.println(clientManager.getClients().keySet().iterator().next());				

				//svap.setOFMessageList(svapManager.getDefaultOFModList(ipaddr));
			}

           br.close();

		} 
        catch (FileNotFoundException e) 
        {
			// skip
		} 
        catch (IOException e) 
        {
			e.printStackTrace();
		}

        // svap timeout, port, and ssid-list
        String timeoutStr = configOptions.get("idlesvapTimeout");
        if (timeoutStr != null) 
        {
        	int timeout = Integer.parseInt(timeoutStr);
        	
        	if (timeout > 0) 
        	{
        		idlesvapTimeout = timeout;
        	}
        }
        
        int port = DEFAULT_PORT;
        String portNum = configOptions.get("masterPort");
        if (portNum != null) 
        {
            port = Integer.parseInt(portNum);
        }
        
        IThreadPoolService tp = context.getServiceImpl(IThreadPoolService.class);
        executor = tp.getScheduledExecutor();
        // Spawn threads for different services
        executor.execute(new MAgentProtocolServer(this, port, executor));
        
        // Spawn applications
        for (Application app: applicationList) 
        {
        	executor.execute(app);
        }
	}

	/** IOFSwitchListener methods **/
	
	

	@Override
	public String getName() 
	{
		return "WirelessMaster";
	}

	
	public void removedSwitch(IOFSwitch sw) 
	{
		// Not all OF switches are M agents. We should immediately remove
		// any associated M agent then.		
		final InetAddress switchIpAddr = ((InetSocketAddress) sw.getInetAddress()).getAddress();
		agentManager.removeAgent(switchIpAddr);		
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		
		// We use this to pick up oc.getSvap().getAgent()DHCP response frames
		// and update a client's IP address details accordingly
		
		Ethernet frame = IFloodlightProviderService.bcStore.get(cntx, 
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		IPacket payload = frame.getPayload(); // IP
        if (payload == null)
        	return Command.CONTINUE;
        
        IPacket p2 = payload.getPayload(); // TCP or UDP
        
        if (p2 == null) 
        	return Command.CONTINUE;
        
        IPacket p3 = p2.getPayload(); // Application
        if ((p3 != null) && (p3 instanceof DHCP)) 
        {
        	DHCP packet = (DHCP) p3;
        	try 
        	{

        		final MACAddress clientHwAddr = MACAddress.valueOf(packet.getClientHardwareAddress().toString());
        		final MClient mc = clientManager.getClients().get(clientHwAddr);
        		
    			// Don't bother if we're not tracking the client
        		// or if the client is unassociated with the agent
        		// or the agent's switch hasn't been registered yet
        		if (mc == null || mc.getSvap().getAgents() == null || !mc.getSvap().AgentsHaveSwitch()) 
        		{
        			return Command.CONTINUE;
        		}
        		
        		// Look for the Your-IP field in the DHCP packet
        		if (packet.getYourIPAddress().getInt() != 0) 
        		{
        			
        			// int -> byte array -> InetAddr
        			final byte[] arr = ByteBuffer.allocate(4).putInt(packet.getYourIPAddress().getInt()).array();
        			final InetAddress yourIp = InetAddress.getByAddress(arr);
        			
        			// No need to invoke agent update protocol if the node
        			// is assigned the same IP
        			if (yourIp.equals(mc.getIpAddress())) 
        			{
        				return Command.CONTINUE;
        			}
        			
        			log.info("Updating client: " + clientHwAddr + " with ipAddr: " + yourIp);
        			mc.setIpAddress(yourIp);
        			//mc.getSvap().setOFMessageList(svapManager.getDefaultOFModList(yourIp));
        			
        			// Push flow messages associated with the client
        			for(IMAgent ma:mc.getSvap().getAgents())
        			{
        				//ma.getSwitch().write(mc.getSvap().getOFMessageList(), null);
        				svapManager.getDefaultOFModList(ma.getSwitch(),yourIp);
        			}

        			for(IMAgent ma:mc.getSvap().getAgents())
        			{ 
        				System.out.println("Update the IpAddress of client "+mc.getMacAddress()+" on Agent "+ma.getIpAddress().getHostAddress());
        				ma.updateClientSvap(mc);
        			}
        		}
        		
			}
        	catch (UnknownHostException e) 
        	{
				// Shouldn't ever happen
				e.printStackTrace();
			}
        }
        
		return Command.CONTINUE;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{
		return false;
	}
	
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return false;
	}
	
	/**
	 * Push the subscription list to the agent
	 * 
	 * @param ma agent to push subscription list to
	 */
	private void pushSubscriptionListToAgent (final IMAgent ma) 
	{
		ma.setSubscriptions(subscriptionList);
	}

	private void updateAgentLastHeard (InetAddress odinAgentAddr) 
	{
		IMAgent agent = agentManager.getAgent(odinAgentAddr);
		
		if (agent != null) 
		{
			// Update last-heard for failure detection
			agent.setLastHeard(System.currentTimeMillis());
		}
	}
	

	private class MAgentsvapAddRunnable implements Runnable
	{
		final IMAgent ma;
		final MClient mc;
		
		MAgentsvapAddRunnable(IMAgent newAgent, MClient mc) 
		{
			this.ma = newAgent;
			this.mc = mc;
		}
		@Override
		public void run() 
		{
			ma.addClientSvap(mc);
		}
		
	}
	
	private class MAgentsvapRemoveRunnable implements Runnable 
	{
		final IMAgent ma;
		final MClient mc;
		
		MAgentsvapRemoveRunnable(IMAgent ma, MClient mc) 
		{
			this.ma = ma;
			this.mc = mc;
		}
		@Override
		public void run() 
		{
			ma.removeClientSvap(mc);
		}
		
	}
	
	private class MAgentSendProbeResponseRunnable implements Runnable
	{
		final IMAgent ma;
		final MACAddress clientHwAddr;
		final MACAddress bssid;
		final Set<String> ssidList;
		
		MAgentSendProbeResponseRunnable(IMAgent ma, MACAddress clientHwAddr, MACAddress bssid, Set<String> ssidList) 
		{
			this.ma = ma;
			this.clientHwAddr = clientHwAddr;
			this.bssid = bssid;
			this.ssidList = ssidList;
		}
		@Override
		public void run() 
		{
			ma.sendProbeResponse(clientHwAddr, bssid, ssidList);
		}		
	}
	
	private class IdlesvapReclaimTask implements Runnable 
	{
		private final MClient oc;
		
		IdlesvapReclaimTask(final MClient oc) 
		{
			this.oc = oc;
		}
		
		@Override
		public void run()
		{
			MClient client = clientManager.getClients().get(oc.getMacAddress());
			Set<IMAgent> agents=client.getSvap().getAgents();
			for(IMAgent ag:agents)
			{
				System.out.println("Client: "+client.getMacAddress()+"/"+client.getIpAddress().getHostAddress().toString()+", on Agent: "+ ag.getIpAddress().getHostAddress().toString());		
			}
			if (client == null) 
			{
				return;
			}
			
			// Client didn't follow through to connect
			try 
			{
				if (client.getIpAddress().equals(InetAddress.getByName("0.0.0.0"))) 
				{
					Set<IMAgent> ags=client.getSvap().getAgents();
					for(IMAgent agent:ags)
					{
						if (agent != null) 
						{
							log.info("Clearing svap " + client.getMacAddress() + 
								" from agent:" + agent.getIpAddress().getHostAddress().toString() + " due to inactivity");
							poolManager.removeClientPoolMapping(client);
							agent.removeClientSvap(client);
							clientManager.removeClient(client.getMacAddress());
						}
					}
				}
			} 
			catch (UnknownHostException e) 
			{
				// skip
			}
		}
	}

	private class SubscriptionCallbackTuple 
	{
		EventSubscription oes;
		NotificationCallback cb;
	}

	@Override
	public void switchAdded(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchRemoved(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchActivated(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port,
			PortChangeType type) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchChanged(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}
}
