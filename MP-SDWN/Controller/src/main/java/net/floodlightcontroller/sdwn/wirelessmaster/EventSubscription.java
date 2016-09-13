package net.floodlightcontroller.sdwn.wirelessmaster;

import net.floodlightcontroller.util.MACAddress;


/**
 * 
 * SDWN Applications should use instances of this class to express
 * subscription requests. One instance of this class represents
 * a single subscription request against a single statistic.
 * 
 * FIXME: The application should ensure it doesn't install the same
 * subscription twice.
 * 
 * @author Lalith Suresh <suresh.lalith@gmail.com>
 *
 */
public class EventSubscription 
{

	private final String WILD_CARD = "*";
	public enum Relation 
	{
	    EQUALS,
	    GREATER_THAN,
	    LESSER_THAN,
	};
	
	private String client;
	private String statistic;
	private Relation relation;
	private double value;
	
	/**
	 * @return the client
	 */
	public String getClient() 
	{
		return client;
	}

	/**
	 * @return the statistic
	 */
	public String getStatistic() 
	{
		return statistic;
	}
	
	/**
	 * @return the relation
	 */
	public Relation getRelation() 
	{
		return relation;
	}

	/**
	 * @return the value
	 */
	public double getValue() 
	{
		return value;
	}
	
	/**
	 * Sets a subscription for an event, defined per client (or 
	 * for all clients using *), for a particular statistic that
	 * satisfies a particular relation with a defined value.
	 * 
	 * @param client client to be matched against. Should be a valid MAC addrress or wild-card.
	 * @param statistic any string which is a statistic. This field will be ignored by agents
	 * 		  which do not understand the requested statistic.
	 * @param rel a numerical relation with the said statistic
	 * @param value value to compare the statistic with using relation 'rel'
	 */
	public void setSubscription (String client, String stat, Relation rel, double val) 
	{
		// Sanity checking
		try 
		{
			MACAddress.valueOf(client);
		} 
		catch (IllegalArgumentException e) 
		{
			if (!client.equals(WILD_CARD)) 
			{
				throw new IllegalArgumentException();
			}
		}
		
		this.client = client;
		this.statistic = stat;
		this.relation = rel;
		this.value = val;
	}
}

