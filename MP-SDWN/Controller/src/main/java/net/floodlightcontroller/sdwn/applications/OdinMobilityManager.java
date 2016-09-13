package net.floodlightcontroller.sdwn.applications;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import net.floodlightcontroller.sdwn.wirelessmaster.NotificationCallback;
import net.floodlightcontroller.sdwn.wirelessmaster.NotificationCallbackContext;
import net.floodlightcontroller.sdwn.wirelessmaster.Application;
import net.floodlightcontroller.sdwn.wirelessmaster.MClient;
import net.floodlightcontroller.sdwn.wirelessmaster.EventSubscription;
import net.floodlightcontroller.sdwn.wirelessmaster.WirelessMaster;
import net.floodlightcontroller.sdwn.wirelessmaster.EventSubscription.Relation;
import net.floodlightcontroller.util.MACAddress;

public class OdinMobilityManager extends Application 
{
	protected static Logger log = LoggerFactory.getLogger(OdinMobilityManager.class);	
	private ConcurrentMap<MACAddress, MobilityStats> clientMap = new ConcurrentHashMap<MACAddress, MobilityStats> ();
	private final long HYSTERESIS_THRESHOLD; // milliseconds
	private final long IDLE_CLIENT_THRESHOLD; // milliseconds
	private final long SIGNAL_STRENGTH_THRESHOLD; // dbm

	public OdinMobilityManager () 
	{
		this.HYSTERESIS_THRESHOLD = 3000;
		this.IDLE_CLIENT_THRESHOLD = 4000;
		this.SIGNAL_STRENGTH_THRESHOLD = 15;
	}
	
	// Used for testing
	public OdinMobilityManager (long hysteresisThresh, long idleClientThresh, long signalStrengthThresh) 
	{
		this.HYSTERESIS_THRESHOLD = hysteresisThresh;
		this.IDLE_CLIENT_THRESHOLD = idleClientThresh;
		this.SIGNAL_STRENGTH_THRESHOLD = signalStrengthThresh;
	}
	
	/**
	 * Register subscriptions
	 */
	private void init () 
	{
		System.out.println("Run OdinMobilityManager...");
		EventSubscription oes = new EventSubscription();
		oes.setSubscription("50:a4:c8:d3:73:73", "signal", Relation.GREATER_THAN, 160);		
		
		NotificationCallback cb = new NotificationCallback() 
		{
			
			@Override
			public void exec(EventSubscription oes, NotificationCallbackContext cntx) 
			{
				handler(oes, cntx);
			}
		};
		
		registerSubscription(oes, cb);
	}
	
	@Override
	public void run() 
	{
		init (); 
		
		// Purely reactive, so end.
	}
	
	
	/**
	 * This handler will handoff a client in the event of its
	 * agent having failed.
	 * 
	 * @param oes
	 * @param cntx
	 */
	private void handler (EventSubscription oes, NotificationCallbackContext cntx) 
	{
		// Check to see if this is a client we're tracking
		MClient client = getClientFromHwAddress(cntx.clientHwAddress);
		log.debug("Mobility manager: notification from " + cntx.clientHwAddress + " from agent " + cntx.agent.getIpAddress() + " val: " + cntx.value + " at " + System.currentTimeMillis());
		
		if (client == null)
			return;
				
		long currentTimestamp = System.currentTimeMillis();
		
		// Assign mobility stats object if not already done
		if (!clientMap.containsKey(cntx.clientHwAddress)) 
		{
			clientMap.put(cntx.clientHwAddress, new MobilityStats(cntx.value, currentTimestamp, currentTimestamp));
		}
		
		MobilityStats stats = clientMap.get(cntx.clientHwAddress);
		
		// If client hasn't been assigned an agent, do so
		if (client.getSvap().getAgents() == null) 
		{
			log.info("Mobility manager: handing off client " + cntx.clientHwAddress
									+ " to agent " + cntx.agent.getIpAddress() + " at " + System.currentTimeMillis());
			handoffClientToAp(cntx.clientHwAddress, cntx.agent.getIpAddress());
			updateStatsWithReassignment (stats, cntx.value, currentTimestamp); 
			return;
		}
		
		// Check for out-of-range client
		if ((currentTimestamp - stats.lastHeard) > IDLE_CLIENT_THRESHOLD) 
		{
			log.info("Mobility manager: handing off client " + cntx.clientHwAddress
					+ " to agent " + cntx.agent.getIpAddress() + " at " + System.currentTimeMillis());
			handoffClientToAp(cntx.clientHwAddress, cntx.agent.getIpAddress());
			updateStatsWithReassignment (stats, cntx.value, currentTimestamp);	
			return;
		}
		
		// If this notification is from the agent that's hosting the client's LVAP. update MobilityStats.
		// Else, check if we should do a handoff.
		if (((MClient) client.getSvap().getAgents()).getIpAddress().equals(cntx.agent.getIpAddress())) 
		{
			stats.signalStrength = cntx.value;
			stats.lastHeard = currentTimestamp;
		}
		else 
		{			
			// Don't bother if we're not within hysteresis period
			if (currentTimestamp - stats.assignmentTimestamp < HYSTERESIS_THRESHOLD)
				return;
			
			// We're outside the hysteresis period, so compare signal strengths for a handoff
			if (cntx.value >= stats.signalStrength + SIGNAL_STRENGTH_THRESHOLD) 
			{
				log.info("Mobility manager: handing off client " + cntx.clientHwAddress
						+ " to agent " + cntx.agent.getIpAddress() + " at " + System.currentTimeMillis());
				handoffClientToAp(cntx.clientHwAddress, cntx.agent.getIpAddress());
				updateStatsWithReassignment (stats, cntx.value, currentTimestamp);
				return;
			}
		}
	}
	
	private void updateStatsWithReassignment (MobilityStats stats, long signalValue, long now)
	{
		stats.signalStrength = signalValue;
		stats.lastHeard = now;
		stats.assignmentTimestamp = now;
	}
	
	
	private class MobilityStats 
	{
		public long signalStrength;
		public long lastHeard;
		public long assignmentTimestamp;
		
		public MobilityStats (long signalStrength, long lastHeard, long assignmentTimestamp) 
		{
			this.signalStrength = signalStrength;
			this.lastHeard = lastHeard;
			this.assignmentTimestamp = assignmentTimestamp;
		}
	}
}
