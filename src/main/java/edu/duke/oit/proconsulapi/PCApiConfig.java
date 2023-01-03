package edu.duke.oit.proconsulapi;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;


public class PCApiConfig {

	private static PCApiConfig config = null;
	private Properties properties = null;
	
	private PCApiConfig() {
		properties = new Properties();
		
		// First, look for the file in /etc/proconsul/proconsulapi.properties.  Only use the embedded one if that fails.
		InputStream etcfile = null;
		InputStream inputStream = null;
		
		try {
			etcfile = new FileInputStream("/etc/proconsul/proconsulapi.properties");
			properties.load(etcfile);
		} catch (Exception f) {
			
			ClassLoader cl = PCApiConfig.class.getClassLoader();
			URL url = cl.getResource("proconsulapi.properties");
		
			try {
				inputStream = url.openStream();
				properties.load(inputStream);
			} catch (Exception e) {
				throw new RuntimeException("problem loading configuration");
			}
		} finally { 
			if (inputStream != null) {
				try {
					inputStream.close();
				}catch (Exception e) {
					// ignore
				}
			}
			if (etcfile != null) {
				try {
					etcfile.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	/**
	 *
	 * @return config
	 */
	public static PCApiConfig getInstance() {
		if (config == null) {
			config = new PCApiConfig();
		}
		return config;
	}
	
	/**
	 * get property
	 * @param property
	 * @param exceptionIfNotFound
	 * @return property value
	 */
	public String getProperty(String property, boolean exceptionIfNotFound) {
		String value = properties.getProperty(property);
		if (value == null && exceptionIfNotFound) {
			throw new RuntimeException("property: " + property + " not found");
		}
		return value;
	}
		
}
