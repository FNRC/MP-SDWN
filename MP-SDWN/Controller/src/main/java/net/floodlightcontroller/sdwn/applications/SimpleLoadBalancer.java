package net.floodlightcontroller.sdwn.applications;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import net.floodlightcontroller.sdwn.wirelessmaster.Application;
import net.floodlightcontroller.sdwn.wirelessmaster.MClient;
import net.floodlightcontroller.util.MACAddress;

public class SimpleLoadBalancer extends Application {

	private final int INTERVAL = 60000;
	private final int SIGNAL_THRESHOLD = 160;

	HashSet<MClient> clients;
	Map<MACAddress, Set<InetAddress>> hearingMap = new HashMap<MACAddress, Set<InetAddress>> ();
	Map<InetAddress, Integer> newMapping = new HashMap<InetAddress, Integer> ();
	
	
	@Override
	public void run() {
		
System.out.println("3333333333333333");
		while (true) {
			try {

				Thread.sleep(INTERVAL);
								
				clients = new HashSet<MClient>(getClients());

				hearingMap.clear();
				newMapping.clear();
				
				/*
				 * Probe each AP to get the list of MAC addresses that it can "hear".
				 * We define "able to hear" as "signal strength > SIGNAL_THRESHOLD".
				 * 
				 *  We then build the hearing table.
				 */
				for (InetAddress agentAddr: getAgents()) {
					Map<MACAddress, Map<String, String>> vals = getRxStatsFromAgent(agentAddr);
					
					for (Entry<MACAddress, Map<String, String>> vals_entry: vals.entrySet()) {
						
						MACAddress staHwAddr = vals_entry.getKey();
						
						for (MClient mc: clients) {
							if (mc.getMacAddress().equals(staHwAddr)
									&& mc.getIpAddress() != null
									&& !mc.getIpAddress().getHostAddress().equals("0.0.0.0")
									&& Integer.parseInt(vals_entry.getValue().get("signal")) >= SIGNAL_THRESHOLD) {
							
								if (!hearingMap.containsKey(staHwAddr))
									hearingMap.put(staHwAddr, new HashSet<InetAddress> ());
									
								hearingMap.get(staHwAddr).add(agentAddr);
							}
						}
							
					}
				}
				
				balance();
				
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}
	
	private void balance() {
		
		if (hearingMap.size() == 0)
			return;
		
		/*
		 *  Now that the hearing map is populated, we re-assign
		 *  clients to each AP in a round robin fashion, constrained
		 *  by the hearing map.
		 */
		for (MClient client: clients) {

			InetAddress minNode = null;
			int minVal = 0;
			
			if ( client.getIpAddress() == null
					|| client.getIpAddress().getHostAddress().equals("0.0.0.0"))
				continue;
			
			if(hearingMap.get(client.getMacAddress()) == null) {
				System.err.println("Skipping for client: " + client.getMacAddress());
				continue;
			}
				
				
			for (InetAddress agentAddr: hearingMap.get(client.getMacAddress())) {
										
				if (!newMapping.containsKey(agentAddr)) {
					newMapping.put(agentAddr, 0);
				}
				
				int val = newMapping.get(agentAddr);
				
				if (minNode == null || val < minVal) {
					minVal = val;
					minNode = agentAddr;
				}
			}

			if (minNode == null)
				continue;
			
			handoffClientToAp(client.getMacAddress(), minNode);
			newMapping.put (minNode, newMapping.get(minNode) + 1);
		}
	}
}
