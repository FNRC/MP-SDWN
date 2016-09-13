package net.floodlightcontroller.sdwn.wirelessmaster;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.sdwn.wirelessmaster.IMAgent;
import net.floodlightcontroller.sdwn.wirelessmaster.MAgentFactory;
import net.floodlightcontroller.sdwn.wirelessmaster.MClient;
import net.floodlightcontroller.sdwn.wirelessmaster.WirelessMaster;


class AgentManager 
{
	private final ConcurrentHashMap<InetAddress, IMAgent> agentMap = new ConcurrentHashMap<InetAddress,IMAgent>();
    protected static Logger log = LoggerFactory.getLogger(WirelessMaster.class);
    
    private IFloodlightProviderService floodlightProvider;
    private final ClientManager clientManager;
    protected IOFSwitchService switchService;
    private final PoolManager poolManager;
    
	private final Timer failureDetectionTimer = new Timer();
	private int agentTimeout = 6000;

	protected AgentManager (ClientManager clientManager, PoolManager poolManager) 
	{
		this.clientManager = clientManager;
		this.poolManager = poolManager;
	}
 
	protected void setFloodlightProvider(final IFloodlightProviderService provider, IOFSwitchService switchser) 
	{
    	floodlightProvider = provider;
    	switchService=switchser;
    }
    
    
    protected void setAgentTimeout (final int timeout) 
    {
    	assert (timeout > 0);
    	agentTimeout = timeout;
    }
    
    
    /**
	 * Confirm if the agent corresponding to an InetAddress
	 * is being tracked.
	 * 
	 * @param odinAgentInetAddress
	 * @return true if the agent is being tracked
	 */
	protected boolean isTracked(final InetAddress MAgentInetAddress) 
	{
		return agentMap.containsKey(MAgentInetAddress);
	}
	
	
	/**
	 * Get the list of agents being tracked for a particular pool
	 * @return agentMap
	 */
	protected Map<InetAddress, IMAgent> getAgents() 
	{
		return Collections.unmodifiableMap(agentMap);
	}
	
	
	/**
	 * Get a reference to an agent
	 * 
	 * @param agentInetAddr
	 */
	protected IMAgent getAgent(final InetAddress agentInetAddr) 
	{
		assert (agentInetAddr != null);
		return agentMap.get(agentInetAddr);
	}
	
	
	/**
	 * Removes an agent from the agent manager
	 * 
	 * @param agentInetAddr
	 */
	protected void removeAgent(InetAddress agentInetAddr) 
	{
		synchronized (this) 
		{
			agentMap.remove(agentInetAddr);
		}
	}
	
	// Handle protocol messages here
	
	/**
     * Handle a ping from an agent. If an agent was added to the
     * agent map, return true.
     * 
     * @param odinAgentAddr
     * @return true if an agent was added
     */
	protected boolean receivePing(final InetAddress MAgentAddr) 
	{
		log.info("Ping message from: " + MAgentAddr.getHostAddress().toString());
		
    	/* 
    	 * If this is not the first time we're hearing from this
    	 * agent, then skip.
    	 */
    	if (MAgentAddr == null || isTracked (MAgentAddr)) 
    	{
    		return false;
    	}
    	
    	IOFSwitch ofSwitch = null;
    	
		/* 
		 * If the OFSwitch corresponding to the agent has already
		 * registered here, then set it in the OdinAgent object.
		 * We avoid registering the agent until its corresponding
		 * OFSwitch has done so.
		 */
		for (IOFSwitch sw:  switchService.getAllSwitchMap().values()) 
		{
			
		//	log.info("111111111111111111111111111111111111"+ sw +"&&&&&&&&&&&&&"+ switchService.getAllSwitchMap().values());
			/* 
			 * We're binding by IP addresses now, because we want to pool
			 * an OFSwitch with its corresponding OdinAgent, if any.
			 */
			String switchIpAddr = ((InetSocketAddress) sw.getInetAddress()).getAddress().getHostAddress();
			//String switchIpAddr="172.23.22.7";
		//	log.info("999999999999999999999999999999999999 "+ switchIpAddr);
			if (switchIpAddr.equals(MAgentAddr.getHostAddress())) 
			{
				 
				ofSwitch = sw;
			//	log.info("33333333333333333333 "+ ofSwitch);
				break;
			}
		}
		
		if (ofSwitch == null)
			return false;
		
		synchronized (this) 
		{
			
			/* Possible if a thread has waited
			 * outside this critical region for
			 * too long
			 */
			if (isTracked(MAgentAddr))
				return false;
			
			IMAgent ma = MAgentFactory.getMAgent();
			ma.setSwitch(ofSwitch);
			ma.init(MAgentAddr);
			ma.setLastHeard(System.currentTimeMillis());
			List<String> poolListForAgent = poolManager.getPoolsForAgent(MAgentAddr);
    		
    		/* 
    		 * It is possible that the controller is recovering from a failure,
    		 * so query the agent to see what SVAPs it hosts, and add them
    		 * to our client tracker accordingly.
    		 */
    		for (MClient client: ma.getSvapsRemote()) 
    		{
    			
    			MClient trackedClient = clientManager.getClients().get(client.getMacAddress());
    			
    			if (trackedClient == null)
    			{
    				clientManager.addClient(client);
    				trackedClient = clientManager.getClients().get(client.getMacAddress());
    				
    				/* 
    				 * We need to find the pool the client was previously assigned to.
    				 * The only information we have at this point is the
    				 * SSID list of the client's SVAP. This can be simplified in
    				 * future by adding a "pool" field to the SVAP struct.
    				 */
    				            				
    				for (String pool: poolListForAgent) 
    				{
    					/* 
    					 * Every SSID in every pool is unique, so we need to use only one
    					 * of the svap's SSIDs to find the right pool.
    					 */            					
    					String ssid = client.getSvap().getSsids().get(0); 
    					if (poolManager.getSsidListForPool(pool).contains(ssid)) 
    					{
    						poolManager.mapClientToPool(trackedClient, pool);
    						break;
    					}
    						
    				}
    			}
    			
    			if (trackedClient.getSvap().getAgents() == null) 
    			{
    				if(!trackedClient.getSvap().getAgents().contains(ma))
    					trackedClient.getSvap().getAgents().add(ma);
    			}
    			else
    			{
    				for(IMAgent agent:trackedClient.getSvap().getAgents())
    				{
    					if(agent.getIpAddress().equals(MAgentAddr))
    					{	
    						break;//若某个用户存在一个关联的Agent，则不做任何操作
    					}
        			/* 
        			 * Race condition: 
        			 * - client associated at AP1 before the master failure,
        			 * - master crashes.
        			 * - master re-starts, AP2 connects to the master first.
        			 * - client scans, master assigns it to AP2.
        			 * - AP1 now joins the master again, but it has the client's SVAP as well.
        			 * - Master should now clear the SVAP from AP1.
        			 */
    				}
    				ma.removeClientSvap(client);
    			}
    		}
    		
   			agentMap.put(MAgentAddr, ma);
		
    		log.info("Adding Agent to map: " + MAgentAddr.getHostAddress().toString());
    		
    		/* This TimerTask checks the lastHeard value
    		 * of the agent in order to handle failure detection
    		 */
    		failureDetectionTimer.scheduleAtFixedRate(new OdinAgentFailureDetectorTask(ma), 1, agentTimeout/2);
		}
    	
		return true;
	}
	
	
	private class OdinAgentFailureDetectorTask extends TimerTask 
	{
		private final IMAgent agent;
		
		OdinAgentFailureDetectorTask (final IMAgent oa)
		{
			this.agent = oa;
		}
		
		@Override
		public void run() 
		{
			log.info("Executing failure check against: " + agent.getIpAddress().getHostAddress().toString());
			if ((System.currentTimeMillis() - agent.getLastHeard()) >= agentTimeout) 
			{
				log.error("Agent: " + agent.getIpAddress().getHostAddress().toString() + " has timed out");
				
				/* This is default behaviour, maybe we should
				 * re-assign the client based on some specific
				 * behaviour
				 */
				
				// TODO: There should be a way to lock the master
				// during such operations	
				for (MClient oc: agent.getSvapsLocal()) 
				{
					clientManager.getClients().get(oc.getMacAddress()).getSvap().setAgents(new HashSet<IMAgent> ());
				}
				
				// Agent should now be cleared out
				removeAgent(agent.getIpAddress());
				this.cancel();
			}
		}		
	}
}
