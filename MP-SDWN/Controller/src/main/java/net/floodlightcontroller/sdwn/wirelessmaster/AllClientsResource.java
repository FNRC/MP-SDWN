package net.floodlightcontroller.sdwn.wirelessmaster;

import java.util.Set;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class AllClientsResource extends ServerResource 
{

	@Get("json")
    public Set<MClient> retreive() 
    {
    	WirelessMaster mc = (WirelessMaster) getContext().getAttributes().
        					get(WirelessMaster.class.getCanonicalName());
    	
    	return mc.getClients(PoolManager.GLOBAL_POOL);
    }
}
