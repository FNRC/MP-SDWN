package net.floodlightcontroller.sdwn.wirelessmaster;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

//import org.openflow.protocol.OFFlowMod;
//import org.openflow.protocol.OFMatch;
//import org.openflow.protocol.OFMessage;
//import org.openflow.protocol.action.OFAction;
//import org.openflow.protocol.action.OFActionDataLayerDestination;
//import org.openflow.protocol.action.OFActionOutput;
//import org.openflow.util.U16;



import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.util.MACAddress;

public class SvapManager 
{
			
	/**
	 * Get the default flow table entries that SDWN associates
	 * with each SVAP
	 * 
	 * @param inetAddr IP address to use for the flow
	 * @return a list of flow mods
	 */
	public void getDefaultOFModList(IOFSwitch ofSwitch,InetAddress inetAddr) 
	{
		OFFlowAdd.Builder flow1 = OFFactories.getFactory(OFVersion.OF_10).buildFlowAdd();
		{
			Match.Builder match1 = OFFactories.getFactory(OFVersion.OF_10).buildMatch();
			ArrayList<OFAction> actionList1 = new ArrayList<OFAction>();
			OFActionOutput.Builder action1 = OFFactories.getFactory(OFVersion.OF_10).actions().buildOutput();
			match1.setExact(MatchField.IN_PORT,OFPort.of(2) );
			match1.setExact(MatchField.ETH_TYPE, EthType.IPv4);
			match1.setExact(MatchField.IPV4_SRC,IPv4Address.of(inetAddr.getHostAddress()) );
			
			action1.setMaxLen(0xffFFffFF);
			action1.setPort(OFPort.of(1));
			actionList1.add(action1.build());
			
			flow1.setCookie(U64.of(12345));
			flow1.setPriority((short) 200);
			flow1.setMatch(match1.build());
			flow1.setIdleTimeout((short) 0);
			flow1.setActions(actionList1);
			ofSwitch.write(flow1.build());
		}
		
		OFFlowAdd.Builder flow2 = OFFactories.getFactory(OFVersion.OF_10).buildFlowAdd();
		{
			Match.Builder match2 = OFFactories.getFactory(OFVersion.OF_10).buildMatch();
			ArrayList<OFAction> actionList2 = new ArrayList<OFAction>();
			OFActionOutput.Builder action2 = OFFactories.getFactory(OFVersion.OF_10).actions().buildOutput();
			match2.setExact(MatchField.IN_PORT,OFPort.of(1) );
			match2.setExact(MatchField.ETH_TYPE, EthType.IPv4);
			match2.setExact(MatchField.IPV4_DST,IPv4Address.of(inetAddr.getHostAddress()) );
			
			action2.setMaxLen(0xffFFffFF);
			action2.setPort(OFPort.of(2));
			actionList2.add(action2.build());
			
			flow2.setCookie(U64.of(12345));
			flow2.setPriority((short) 200);
			flow2.setMatch(match2.build());
			flow2.setIdleTimeout((short) 0);
			flow2.setActions(actionList2);
			//flow2.setLength(U64.of(80));	
			ofSwitch.write(flow2.build());
		}
		
		/*
	
		ArrayList<OFMessage> list = new ArrayList<OFMessage>();
		
		list.add((OFMessage) flow1);
		list.add((OFMessage) flow2);

		
		return list;
		*/
	}
}