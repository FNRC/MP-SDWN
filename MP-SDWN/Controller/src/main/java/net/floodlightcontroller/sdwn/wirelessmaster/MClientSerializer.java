package net.floodlightcontroller.sdwn.wirelessmaster;

import java.io.IOException;

//import org.codehaus.jackson.JsonGenerator;
//import org.codehaus.jackson.JsonProcessingException;
//import org.codehaus.jackson.map.JsonSerializer;
//import org.codehaus.jackson.map.SerializerProvider;
import java.util.*;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class MClientSerializer extends JsonSerializer<MClient> 
{
	@Override
	public void serialize(MClient client, JsonGenerator jgen,
			SerializerProvider provider) throws IOException,
			JsonProcessingException 
	{
		jgen.writeStartObject();
		jgen.writeStringField("macAddress", client.getMacAddress().toString());
		String clientIpAddr = client.getIpAddress().getHostAddress();
		jgen.writeStringField("ipAddress", clientIpAddr);
		jgen.writeStringField("lvapBssid", client.getSvap().getBssid().toString());
		jgen.writeStringField("lvapSsid", client.getSvap().getSsids().get(0)); // FIXME: assumes single SSID
		Set<IMAgent> agents = client.getSvap().getAgents();
		if (agents != null) 
		{
			for(IMAgent agent:agents)
			{
				String agentIpAddr = agent.getIpAddress().getHostAddress();
				jgen.writeStringField("agent", agentIpAddr);
			}
		}
		else 
		{
			jgen.writeStringField("agents", null);
		}	
		jgen.writeEndObject();
	}
}