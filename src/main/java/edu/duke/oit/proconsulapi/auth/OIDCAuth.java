package edu.duke.oit.proconsulapi.auth;


import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.ehcache.Cache;
import org.ehcache.CacheManager;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.CacheManagerBuilder;
import org.ehcache.config.builders.ExpiryPolicyBuilder;
import org.ehcache.config.builders.ResourcePoolsBuilder;
import org.ehcache.expiry.ExpiryPolicy;

import edu.duke.oit.proconsulapi.PCApiConfig;

public class OIDCAuth implements BasicAuthHandler {

	private static CacheManager manager = null;
	private static Cache<String,String> cache = null;
	
	@Override
	public boolean validateCredential(String user, String credential,PCApiConfig config) {
		
		// We perform introspection on the passed-in credential.
		// The user specified is expected to match the "sub" claim in the
		// OIDC token, which is passed as the credential. 
		// If the response from the OIDC introspection endpoint to 
		// the request indicates the token has expired, is revoked, 
		// or does not match the claimed user (sub != user) we return
		// false, otherwise, true.
		//
		// For performance purposes, we maintain a cache of accepted 
		// credentials in memory using ehcache.  This is a trade off of 
		// sorts -- we avoid round-tripping on multiple calls by the same 
		// client by caching hashes of successfully-validated tokens, but
		// in the process, we decouple token expiration (somewhat) from 
		// the OIDC OP -- a token that's revoked may remain usable in this 
		// context until the ehcache entry for it expires out of the application
		// cache.  As we expect traffic to be low in this application,
		// and we expect that it will be highly bursty, a short cache lifetime
		// (~ 10 minutes) is probably adequate performance protection and 
		// minimizes validation overhead.
		//
		// Cache keys must hash both the token and the username, so that 
		// replay of a valid token for user1 to authN as user2 is not
		// allowed during the lifetime of a cache entry.
		
		// Set up the cache (if not already built)
		// Eschew caching for now - Java 7 doesn't support Duration properly
		/*
		if (manager == null) {
			manager = CacheManagerBuilder.newCacheManagerBuilder().build(true);
			try {
				// Set 10 minute expiration policy for token caching
				ExpiryPolicy<Object,Object> ep = ExpiryPolicyBuilder.timeToLiveExpiration(Duration.of(600,ChronoUnit.SECONDS));

				cache = manager.createCache("creds", CacheConfigurationBuilder.newCacheConfigurationBuilder(String.class,String.class,ResourcePoolsBuilder.heap(1000)).withExpiry(ep));
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		} */
		
		//
		// Get a config object 
		PCApiConfig pcac = PCApiConfig.getInstance();
		
		// And get the relevant URLs and keys
		String iURL = pcac.getProperty("oidc.introspectionURL", false);
		if (iURL == null || iURL.equals("")) {
			// No oidc.introspectionURL specified -- use a default
			iURL = "https://oauth.oit.duke.edu/oidc/introspect";
		}
		
		String clientId = pcac.getProperty("oidc.clientId", true);
		String clientSecret = pcac.getProperty("oidc.clientSecret", true);
		
		// Construct the key for cache checking
		
		// String key = DigestUtils.sha256Hex(user + ":" + credential);
		
		// If this is a cached success, return true
		// No caching for now
		/*
		if (cache != null && cache.containsKey(key)) {
			return (cache.get(key).equals("true"));
		} */
		
		// Otherwise, check with OIDC
		
		String ba = clientId + ":" + clientSecret;
		String auth = Base64.encodeBase64String(ba.getBytes());
		String aval = "Basic " + auth;

		try {
			URL u = new URL(iURL);
						
			HttpsURLConnection hc = (HttpsURLConnection) u.openConnection();
			
			hc.setRequestMethod("POST");
			hc.setRequestProperty("Authorization", aval);
			
			hc.setDoOutput(true);
			String postval = null;
			if (credential.startsWith("token="))
				postval = credential;
			else
				postval = "token="+credential;
			
			OutputStream os = hc.getOutputStream();
			byte[] sent = postval.getBytes();
			os.write(sent,0,sent.length);
			
			BufferedReader br = new BufferedReader(new InputStreamReader(hc.getInputStream()));
			StringBuilder resp = new StringBuilder();
			String read = null;
			while ((read=br.readLine())!=null) {
				resp.append(read.trim());
			}
			
			HashMap<String,String> map = new HashMap<String,String>();
			JsonReaderFactory jrf = Json.createReaderFactory(map);
			
			JsonReader reader = jrf.createReader(new ByteArrayInputStream(resp.toString().getBytes()));
			
			JsonObject jo = reader.readObject();
			
			String sub = jo.getString("sub");
			
			if (sub.equals(user)) {
				return true;
			} else {
				throw new RuntimeException("Sub is " + sub + " while user is " + user);
			}
		} catch (Exception e) {
			throw new RuntimeException("Exception",e);
		}
	}
}
