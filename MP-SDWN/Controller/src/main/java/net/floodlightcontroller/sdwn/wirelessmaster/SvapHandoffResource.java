package net.floodlightcontroller.sdwn.wirelessmaster;

import java.io.IOException;
import java.net.InetAddress;
import java.util.HashMap;

import net.floodlightcontroller.util.MACAddress;




//import org.codehaus.jackson.JsonParseException;
//import org.codehaus.jackson.map.JsonMappingException;
//import org.codehaus.jackson.map.ObjectMapper;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class SvapHandoffResource extends ServerResource 
{
	@SuppressWarnings("unchecked")
	@Post
    public void store(String flowmod) 
	{
    	WirelessMaster mc = (WirelessMaster) getContext().getAttributes().
        					get(WirelessMaster.class.getCanonicalName());
    	
    	ObjectMapper mapper = new ObjectMapper();

		HashMap<String, String> fmdata;
		try 
		{
			fmdata = mapper.readValue(flowmod, HashMap.class);

			String staHwAddress = fmdata.get("clientHwAddress");
	        String apIpAddress= fmdata.get("apIpAddress");
	        String poolName = fmdata.get("poolName");
	    
	        mc.handoffClientToAp(poolName, MACAddress.valueOf(staHwAddress), InetAddress.getByName(apIpAddress));
		} 
		catch (JsonParseException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		catch (JsonMappingException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}
