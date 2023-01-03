package edu.duke.oit.proconsulapi;


public class PCApiDBConnection extends DBConnection {
	
	private static PCApiDBConnection instance = null;
	
	protected PCApiDBConnection() {
		super (PCApiConfig.getInstance().getProperty("pcdb.driver", true),
				PCApiConfig.getInstance().getProperty("pcdb.url", true),
				PCApiConfig.getInstance().getProperty("pcdb.user", true),
				PCApiConfig.getInstance().getProperty("pcdb.password", true));
		
	}
	protected static PCApiDBConnection getInstance() {
		if (instance == null) {
			instance = new PCApiDBConnection();
			
		} 
		return instance;
	}
}
