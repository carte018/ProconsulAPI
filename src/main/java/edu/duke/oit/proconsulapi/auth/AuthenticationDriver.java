/*
 * Copyright 20xx - 20xx Duke University
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License Version 2 as published by
    the Free Software Foundation.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License Version 2
    along with this program.  If not, see <https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt>.
 */
package edu.duke.oit.proconsulapi.auth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;

import org.apache.commons.codec.binary.Base64;

import edu.duke.oit.proconsulapi.PCApiConfig;

//import edu.internet2.consent.copsu.model.LogCriticality;

public class AuthenticationDriver {
	public static String getAuthenticatedUser(HttpServletRequest request,HttpHeaders headers, PCApiConfig config) {
		String retUser = null;
		
		// Get the validator out of the configuration file
		String validator = null;
		try {
			validator = config.getProperty("basicauth.validator.class", true);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		Class<BasicAuthHandler> validatorClass = null;
		try {
			validatorClass = (Class<BasicAuthHandler>) Class.forName(validator);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		BasicAuthHandler v;
		try {
			v = (BasicAuthHandler) (validatorClass.newInstance());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		
		// Get credential information from headers
		List<String> baHeaders = new ArrayList<String>();
		baHeaders = (Arrays.asList(headers.getHeaderString("Authorization").split(",")));
		if (baHeaders == null) {
			return null;  // if no auth header, return null
		}
		String basicAuth=baHeaders.get(0);  // only inspect the first one
		
		if (basicAuth == null || basicAuth.equals("")) {
			return null;  // No logging here -- this could be a routine failed authN on the first request
		}
		
		// Otherwise, we return a userName or null to indicate another authorization is required
		
		String authData[] = basicAuth.split("\\s+");  // get the parts of the header
		String b64 = authData[1];  // basic auth data
		String unb64 = new String(Base64.decodeBase64(b64.getBytes()));
		String parts[] = unb64.split(":");
		if (v.validateCredential(parts[0], parts[1],config)) {
			retUser = parts[0];
		} else {
			retUser = null;
		}
		return retUser;
	}
}
