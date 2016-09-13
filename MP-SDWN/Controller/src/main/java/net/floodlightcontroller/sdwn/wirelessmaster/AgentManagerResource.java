package net.floodlightcontroller.sdwn.wirelessmaster;

import java.net.InetAddress;
import java.util.Set;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class AgentManagerResource extends ServerResource 
{

	@Get("json")
    public Set<InetAddress> retreive() 
    {
    	WirelessMaster wm = (WirelessMaster) getContext().getAttributes().
        					get(WirelessMaster.class.getCanonicalName());
    	
    	return wm.getAgentAddrs(PoolManager.GLOBAL_POOL);
    }
}