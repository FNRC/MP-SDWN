package net.floodlightcontroller.sdwn.wirelessmaster;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import net.floodlightcontroller.util.MACAddress;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class ConnectedClientsResource extends ServerResource 
{

	@Get("json")
    public Map<MACAddress, MClient> retreive() 
    {
    	WirelessMaster mc = (WirelessMaster) getContext().getAttributes().
        					get(WirelessMaster.class.getCanonicalName());
    	
    	Map<MACAddress, MClient> connectedClients = new HashMap<MACAddress, MClient> ();
    	System.out.println("22");
    	for (MClient e: mc.getClients(PoolManager.GLOBAL_POOL)) 
    	{
    		if (!e.getIpAddress().getHostAddress().equals("0.0.0.0")) 
    		{
    			connectedClients.put(e.getMacAddress(), e);
    			System.out.println(e.getMacAddress());
    		}
    	}
    	
    	return connectedClients;
    }
}