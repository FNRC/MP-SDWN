package net.floodlightcontroller.sdwn.wirelessmaster;

import net.floodlightcontroller.util.MACAddress;

public class NotificationCallbackContext 
{
	public final MACAddress clientHwAddress;
	public final IMAgent agent;
	public final long value;
	
	public NotificationCallbackContext(final MACAddress clientHwAddress, final IMAgent agent, final long value) 
	{
		this.clientHwAddress = clientHwAddress;
		this.agent = agent;
		this.value = value;
	}
}