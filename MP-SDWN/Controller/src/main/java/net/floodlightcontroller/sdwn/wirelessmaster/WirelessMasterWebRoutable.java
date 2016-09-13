package net.floodlightcontroller.sdwn.wirelessmaster;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

class WirelessMasterWebRoutable implements RestletRoutable 
{

	@Override
	public String basePath() 
	{
		return "/sdwn";
	}

	@Override
	public Restlet getRestlet(Context context) 
	{
		Router router = new Router(context);
		router.attach("/clients/all/json", AllClientsResource.class);
		router.attach("/clients/connected/json", ConnectedClientsResource.class);
		router.attach("/agents/json", AgentManagerResource.class);
		router.attach("/handoff/json", SvapHandoffResource.class);
		return router;
	}
}