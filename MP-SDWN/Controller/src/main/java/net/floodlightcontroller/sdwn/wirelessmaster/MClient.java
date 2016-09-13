package net.floodlightcontroller.sdwn.wirelessmaster;


import java.net.InetAddress;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import net.floodlightcontroller.util.MACAddress;

//import org.codehaus.jackson.map.annotate.JsonSerialize;

@JsonSerialize(using=MClientSerializer.class)
public class MClient implements Comparable 
{
	private final MACAddress hwAddress;
	private InetAddress ipAddress;
	private Svap svap;
	

	// NOTE: Will need to add security token and temporal keys here later.
	// So make sure to pass MClient through interfaces of other classes
	// as opposed to the 4-svap properties now. 
	
	public MClient (MACAddress hwAddress, InetAddress ipAddress, Svap svap) 
	{
		this.hwAddress = hwAddress;
		this.ipAddress = ipAddress;
		this.svap = svap;
	}
		
	
	/**
	 * STA's MAC address. We assume one per client here.
	 * (Implies, no support for FMC yet) :)
	 * 
	 * @return client's MAC address
	 */
	public MACAddress getMacAddress() 
	{
		return this.hwAddress;
	}
	
		
	/**
	 * Get the clien'ts IP address.
	 * @return
	 */
	public InetAddress getIpAddress() 
	{
		return ipAddress;
	}
	
	
	/**
	 * Set the client's IP address
	 * @param addr
	 */
	public void setIpAddress(InetAddress addr) 
	{
		this.ipAddress = addr;
	}
	
	
	/**
	 * Get the client's svap object
	 * @return svap
	 */
	public Svap getSvap() 
	{
		return svap;
	}
	
	
	/**
	 * Set the client's svap
	 */
	public void setsvap() 
	{
		this.svap = svap;
	}
	
	
	@Override
	public boolean equals(Object obj) 
	{
		if (!(obj instanceof MClient))
			return false;

		if (obj == this)
			return true;
		
		MClient that = (MClient) obj;
			
		return (this.hwAddress.equals(that.hwAddress));
	}

	
	@Override
	public int compareTo(Object o) 
	{
		assert (o instanceof MClient);
		
		if (this.hwAddress.toLong() == ((MClient)o).hwAddress.toLong())
			return 0;
		
		if (this.hwAddress.toLong() > ((MClient)o).hwAddress.toLong())
			return 1;
		
		return -1;
	}
}
