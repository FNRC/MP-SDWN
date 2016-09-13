package net.floodlightcontroller.sdwn.wirelessmaster;

import java.util.ArrayList;
import java.util.List;

public class MAgentFactory 
{
	
	private static String agentType = "MAgent";
	private static List<MClient> lvapList = new ArrayList<MClient> ();
	
	public static void setMAgentType(String type) 
	{
		if (type.equals("MAgent") 
				|| type.equals("MockMAgent"))
		{
			agentType = type;
		}
		else 
		{
			System.err.println("Unknown MAgent type: " + type);
			System.exit(-1);
		}
	}
	
	public static void setMockMAgentLvapList(List<MClient> list) 
	{
		if (agentType.equals("MockMAgent")) 
		{
			lvapList = list;
		}
	}
	
	public static IMAgent getMAgent() 
	{
		if (agentType.equals("MAgent"))
		{
			return new MAgent();
		}
		else if (agentType.equals("MockMAgent")) 
		{
			StubMAgent sma = new StubMAgent();
			
			for (MClient client: lvapList) 
			{
				sma.addClientSvap(client);
			}
			
			return sma;
		}
		
		return null;
	}
}
