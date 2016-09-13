package net.floodlightcontroller.sdwn.wirelessmaster;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

//import org.codehaus.jackson.JsonGenerator;
//import org.codehaus.jackson.JsonProcessingException;
//import org.codehaus.jackson.map.JsonSerializer;
//import org.codehaus.jackson.map.SerializerProvider;

public class MAgentSerializer extends JsonSerializer<IMAgent> 
{

	public void serialize(IMAgent agent, JsonGenerator jgen,
			SerializerProvider provider) throws IOException,
			JsonProcessingException
	{
		jgen.writeStartObject();
		String blah = agent.getIpAddress().getHostAddress();
		jgen.writeStringField("ipAddress", blah);
		jgen.writeStringField("lastHeard", String.valueOf(agent.getLastHeard()));
		jgen.writeEndObject();
	}
}
