package net.floodlightcontroller.sdwn.applications;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import net.floodlightcontroller.sdwn.wirelessmaster.Application;
import net.floodlightcontroller.sdwn.wirelessmaster.MClient;
import net.floodlightcontroller.util.MACAddress;
//*******************************************************************************//

import java.util.ArrayList;  
import java.util.List;  

 class Value2Key {  
  
    
    private Map<InetAddress,Integer> map=new HashMap<InetAddress,Integer>();  
    
    public Value2Key(Map<InetAddress,Integer> map){  
        this.map=map;  
    }  
    
    public List<InetAddress> getKeys(Integer value){  
        ArrayList<InetAddress> keys=new ArrayList<InetAddress>();  
        for(Entry<InetAddress,Integer> entry:this.map.entrySet()){  
            if(value.equals(entry.getValue())){  
                keys.add(entry.getKey());  
            }else{  
                continue;  
            }  
        }  
        return keys;  
    } 
 }


//*****************************************************************//
public class SmartSection extends Application {
	private final int PERIOD=60000;//1min
	int Threshold=0;
	int countclients=0;
	int countLVAP=0;
	int countVAP=0;
	int sum=0;
	int sumLVAPS=0;
	HashSet<MClient> clients;
	Map <InetAddress,Integer> NLVP= new HashMap<InetAddress,Integer>();//This is used to check numbers of LVAP
	//Map<MACAddress,Set<InetAddress>> ListeningMap= new HashMap<MACAddress, Set<InetAddress>>();//This is used for store informations of clients 
	public void run()
	{
		while(true)
		{
			try{
				NLVP.clear();
				//clients.clear();
				System.out.println("Code is running");
				Thread.sleep(PERIOD);
				clients = new HashSet<MClient>(getClients());
				System.out.println("Start Get the clients of numbers");
				for (MClient oc: clients)//Get the numbers of clients
				{
					countclients++;
					System.out.println("Got nubers of clients"+countclients);
				}
				for(InetAddress agentAddress:getAgents())
				{
				System.out.println("1111111111111111");	
				Map<MACAddress, Map<String, String>> vals = getRxStatsFromAgent(agentAddress);//Get the Sataitics for Agent 
					for (Entry<MACAddress, Map<String, String>> vals_entry: vals.entrySet())
					{
						System.out.println("2222222222222222222");	
						sum=sum+Integer.parseInt(vals_entry.getValue().get("signal"));
						System.out.println("THis is the RSSI value of one client"+Integer.parseInt(vals_entry.getValue().get("signal")));
						countLVAP++;
						
					}
					for(MClient mc: clients)
					{
						if(((MClient) mc.getSvap().getAgents()).getIpAddress().equals(agentAddress))
						{
							countVAP++;	
							System.out.println("This Part show"+countVAP+agentAddress);
						}

					}
					NLVP.put(agentAddress, countVAP);//The numbers of clients that agssined to agent	
					System.out.println(agentAddress+"This number"+countLVAP);
					sumLVAPS=sumLVAPS+countLVAP;//GEt the singal sum of LVAPS
				}
				
				Threshold=sum/sumLVAPS;//Get Threshold  
				System.out.println("Begin the Selection");
				System.out.println(Threshold+"This one");
				BetterChioce();
			}
			catch (InterruptedException e) {
				e.printStackTrace();
			}	
	}
}
private void BetterChioce()
{
	for(InetAddress agentAddress:getAgents())
	{
		Map<MACAddress, Map<String, String>> val2s = getRxStatsFromAgent(agentAddress);
		
		for (Entry<MACAddress, Map<String, String>> val2s_entry: val2s.entrySet())
		{
			MACAddress staHwAddr = val2s_entry.getKey();//Get the MACAddress of the clients 
			for (MClient oc: clients) 
			{
			
			if(oc.getMacAddress().equals(staHwAddr)
					&&oc.getIpAddress() != null
					&&!oc.getIpAddress().getHostAddress().equals("0.0.0.0")
					&&Integer.parseInt(val2s_entry.getValue().get("signal"))<Threshold)//the signal is fine
			{
				System.out.println("The code is running in the Selection Part1");
				//********************************************//
				int [] lnum= new int[2];
				int i=0;
				for(InetAddress agentaddress1: getAgents())
				{
					
				
					lnum[i]=NLVP.get(agentaddress1);
					i++;
					
				}
				int minnum=lnum[0];
				for(int j=0;j<lnum.length;j++)
				{
					if(lnum[j]<minnum)
					{
						minnum=lnum[j];
					}
				}
				//**********************************************//
				/*Integer[] lnum=NLVP.values().toArray(new Integer[20]);
				int minnum=lnum[0];
				for(int i=0;i<lnum.length;i++)
				{
					if(lnum[i]<minnum)
					{
						minnum=lnum[i];
					}
				}
				*/
				System.out.println("minnum"+minnum);
				System.out.println("Have found the best AP");
				Value2Key searcher=new Value2Key(NLVP);  
				System.out.println("Begin to search the AP address");
				InetAddress agentChoiced=searcher.getKeys(minnum).get(0);  
				System.out.println("Begin to handoff");
		        handoffClientToAp(staHwAddr, agentChoiced);//done
		        System.out.println("This is Done ");
		//clients.clear();
			System.out.println("Finished and clean the clients Map");
			//continue;
		        }  
			}
				
			}
			
		}
	}
	
}

