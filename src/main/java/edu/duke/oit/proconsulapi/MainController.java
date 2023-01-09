package edu.duke.oit.proconsulapi;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import edu.duke.oit.proconsulapi.auth.AuthenticationDriver;

/**
 * Handles requests for the administrative API.
 */
@Path("/api")
public class MainController extends Application {
	
	private static final Logger logger = LoggerFactory.getLogger(MainController.class);
	
	// Authorization (minimal at first)
	private boolean isAdmin(HttpServletRequest request, HttpHeaders headers) {
		// for now, get the list from the config file
		PCApiConfig config = PCApiConfig.getInstance();
		String alist = config.getProperty("pcadminlist", true);
		// Construct Headers
	//	HashMap<String,List<String>> hmap = new HashMap<String,List<String>>();
	//	Enumeration<String> n = request.getHeaderNames();
	//	HttpHeaders headers = new HttpHeaders();
		
	//	while (n.hasMoreElements()) {
	//		String hn = n.nextElement();
	//		headers.add(hn, request.getHeader(hn));
	//	}
		
		String authuser = AuthenticationDriver.getAuthenticatedUser(request, headers, config);
		String[] aa = alist.split(",");
		for (String u : aa) {
			if (authuser.equalsIgnoreCase(u)) {
				return true;
			}
		}
		return false;
	}
	
	// Granular authorization for individual panels
	private boolean isDARuleAdmin(HttpServletRequest request, HttpHeaders headers) {
		// Only isAdmin() here
		return isAdmin(request,headers);
	}
	
	private boolean isLoginRuleAdmin(HttpServletRequest request,HttpHeaders headers) {
		// Both general admins and subadmins may be authorized to grant users login access
		PCApiConfig config = PCApiConfig.getInstance();
		String alist = config.getProperty("loginadmins", false);
		if (alist != null) {
			String[] aa = alist.split(",");
			for (String u : aa) {
				if (request.getRemoteUser().equalsIgnoreCase(u)) {
					return true;
				}
			}
		}
		return isAdmin(request,headers);
	}
	
	private boolean isTargetSystemAdmin(HttpServletRequest request, HttpHeaders headers) {
		// Target systems may be administered by subadmins or general admins
		PCApiConfig config = PCApiConfig.getInstance();
		String alist = config.getProperty("targetsystemadmins", false);
		if (alist != null) {
			String[] aa = alist.split(",");
			for (String u : aa) {
				if (request.getRemoteUser().equalsIgnoreCase(u)) {
					return true;
				}
			}
		}
		return isAdmin(request,headers);
	}
	
	private boolean isPosixAdmin(HttpServletRequest request, HttpHeaders headers) {
		// Posix user information may be managed by general admins or subadmins
		PCApiConfig config = PCApiConfig.getInstance();
		String alist = config.getProperty("posixadmins", false);
		if (alist != null) {
			String[] aa = alist.split(",");
			for (String u : aa) {
				if (request.getRemoteUser().equalsIgnoreCase(u)) {
					return true;
				}
			}
		}
		return isAdmin(request,headers);
	}

	private boolean isStaticAdmin(HttpServletRequest request, HttpHeaders headers) {
		// Static user mapping manager
		PCApiConfig config = PCApiConfig.getInstance();
		String alist = config.getProperty("staticadmins",false);
		if (alist != null) {
			String[] aa = alist.split(",");
			for (String u : aa) {
				if (request.getRemoteUser().equalsIgnoreCase(u)) {
					return true;
				}
			}
		}
		// override for now
		return isAdmin(request,headers);
	}
	
	private boolean isGroupAdmin(HttpServletRequest request,HttpHeaders headers) {
		// Only general admins can manage group memberships for dynamic user (since DA is just another group
		// this right amounts to the right to generate DA accounts, albeit in a way that might set off alarms
		return isAdmin(request,headers);
	}
	
	private boolean isTargetProvisioningAdmin(HttpServletRequest request,HttpHeaders headers) {
		// Target system provisioning includes group membership controls, so this too is only available to 
		// general admins
		return isAdmin(request,headers);
	}
	
	@GET
	@Path("/test")
	public Response handleTestGet(@Context HttpServletRequest request,@Context HttpHeaders headers) {		
		if (isAdmin(request,headers)) {
			return Response.status(Status.OK).entity("User IS Admin").build();
		} else {
			return Response.status(Status.OK).entity("User NOT Admin").build();
		}
	}
	
	// API routines for primary administrative activities.  Primary
	// targets are internal operations required to perform provisioning
	// and deprovisioning of user access rights.
	//
	
	// Basic static user management involves simply recording
	// mappings from users to hosts and static target users.
	// The /staticusers endpiont handles basic static user
	// management.  It does *not* manage the creation or 
	// configuration/provisioning of target users -- that's 
	// handled in other endpoints.  
	//
	// There is only one possible targetuser for a given 
	// (eppn,fqdn) pair.
	
	@DELETE
	@Path("/staticusers/{eppn}/{fqdn}")
	public Response handleStaticUsersDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("eppn") String eppn, @PathParam("fqdn") String fqdn) {
		
		// Given a user eppn and fqdn, remove the associated static mapping
		
		PCApiConfig config = PCApiConfig.getInstance();
		Connection conn = null;
		PreparedStatement ps = null;
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database");
		}
		
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		try {
			ps = conn.prepareStatement("delete from static_host where eppn = ? and fqdn = ?");
			if (ps != null) {
				ps.setString(1, eppn);
				ps.setString(2,  fqdn);
				ps.executeUpdate();
				return Response.status(Status.OK).entity("Deleted").build();
			} else {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Deletion failed").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (ps != null) {
				try {
					ps.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@POST
	@Path("/staticusers")
	public Response handleStaticUsersPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		// Given a UserHostMapping, add it to the authorization set
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		// Authorization
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		try {
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<StaticUser> staticusers = new ArrayList<StaticUser>();
		
		if (entity == null || entity.equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("POST body missing").build();
		}
		
		// We accept either a single AccessUserEntry or an array of AccessUserEntry in input JSON
		
		ObjectMapper om = new ObjectMapper().enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
		try {
			staticusers = om.readValue(entity,new TypeReference<List<StaticUser>>(){});
		} catch (Exception e) {
			return Response.status(Status.BAD_REQUEST).entity("Unable to deserialize input").build();
		}
		
		if (staticusers.isEmpty()) {
			return Response.status(Status.BAD_REQUEST).entity("POST requires at least one input object").build();
		}
		int count = 0;
		for (StaticUser su : staticusers) {
			try {
				ps = conn.prepareStatement("select eppn,fqdn from static_host where eppn = ? and fqdn = ?");
				ps.setString(1,su.getEppn());
				ps.setString(2, su.getFqdn());
				if (ps != null) {
					rs = ps.executeQuery();
					if (rs == null || !rs.next()) {
						PreparedStatement ps2 = null;
						ps2 = conn.prepareStatement("insert into static_host values (?,?,?)");
						if (ps2 != null && su.getEppn() != null && su.getFqdn() != null && su.getTargetuser() != null) {
							ps2.setString(1, su.getEppn());
							ps2.setString(2, su.getFqdn());
							ps2.setString(3, su.getTargetuser());
							ps2.executeUpdate();
							count += 1;
							ps2.close();
						} 
					}
				} 
			} catch (Exception e) {
				// ignore exceptions during updates
			}
		}
		
		return Response.status(Status.ACCEPTED).entity("Created " + count + " new bindings").build();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@GET
	@Path("/staticusers")
	public Response handleStaticUsersGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<StaticUser> staticusers = new ArrayList<StaticUser>();
		
		try {
			ps = conn.prepareStatement("select * from static_host");
			if (ps == null) {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database query failure").build();
			}
			
			rs = ps.executeQuery();
			
			while (rs != null && rs.next()) {
				StaticUser su = new StaticUser();
				su.setEppn(rs.getString("eppn"));
				su.setFqdn(rs.getString("fqdn"));
				su.setTargetuser(rs.getString("targetuser"));
				staticusers.add(su);
			}
			
			ps.close();
			if (rs != null) {
				rs.close();
			}
			
			if (! staticusers.isEmpty()) {
				ObjectMapper om = new ObjectMapper();
				String json = om.writeValueAsString(staticusers);
				return Response.status(Status.OK).entity(json.trim()).type("application/json").build();
			} else {
				return Response.status(Status.NOT_FOUND).entity("").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	
	// Domain admin host changes require manual intervention for now.
	// API does not implement interfaces for managing them.
	// If it ever does, they will appear at the /dahosts endpoint
	
	@DELETE
	@Path("/dahosts/{fqdn}")
	public Response handleDAHostsDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("fqdn") String fqdn) {
		return Response.status(Status.ACCEPTED).entity("Not implemented.").build();
	}
	@POST
	@Path("/dahosts")
	public Response handleDAHostsPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		return Response.status(Status.ACCEPTED).entity("Not implemented.").build();
	}
	@GET
	@Path("/dahosts")
	public Response handleDAHostsGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		return Response.status(Status.ACCEPTED).entity("Not implemented.").build();
	}
	
	// Entitlements are not in use at the moment, so we stub out
	// the /dynamicentitlmenthosts endpoints
	//
	
	@DELETE
	@Path("/dynamicentitlementhosts/{urn}/{fqdn}")
	public Response handleDynamicEntitlementHostsDelete(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		return Response.status(Status.ACCEPTED).entity("Not implemented.").build();
	}
	@POST
	@Path("/dynamicentitlementhosts")
	public Response handleDynamicEntitlementHostsPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		return Response.status(Status.ACCEPTED).entity("Not implemented.").build();
	}
	@GET
	@Path("/dynamicentitlementhosts")
	public Response handleDynamicEntitlementHostsGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		return Response.status(Status.ACCEPTED).entity("Not implemented").build();
	}
	
	// The /dynamicgrouphosts endpoint handles authZ for
	// specific FQDNs by members of groups.  Note that assigning
	// dynamic group rights does *not* assign application rights 
	// to the group -- that has to be done separately (or via a 
	// combined endpoint elsewhere -- this is an atomic case).
	//
	
	@DELETE
	@Path("/dynamicgrouphosts/{urn}/{fqdn}")
	public Response handleDynamicGroupHostsDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("urn") String urn, @PathParam("fqdn") String fqdn) {
		
		// Given a user eppn and fqdn, remove the associated UserHostMapping
		
		PCApiConfig config = PCApiConfig.getInstance();
		Connection conn = null;
		PreparedStatement ps = null;
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database");
		}
		
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		try {
			ps = conn.prepareStatement("delete from group_host where groupurn = ? and fqdn = ?");
			if (ps != null) {
				ps.setString(1, urn);
				ps.setString(2,  fqdn);
				ps.executeUpdate();
				return Response.status(Status.OK).entity("Deleted").build();
			} else {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Deletion failed").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (ps != null) {
				try {
					ps.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@POST
	@Path("/dynamicgrouphosts")
	public Response handleDynamicGroupHostsPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		// Given a UserHostMapping, add it to the authorization set
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		// Authorization
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		try {
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<GroupHostMapping> grouphosts = new ArrayList<GroupHostMapping>();
		
		if (entity == null || entity.equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("POST body missing").build();
		}
		
		// We accept either a single AccessUserEntry or an array of AccessUserEntry in input JSON
		
		ObjectMapper om = new ObjectMapper().enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
		try {
			grouphosts = om.readValue(entity,new TypeReference<List<GroupHostMapping>>(){});
		} catch (Exception e) {
			return Response.status(Status.BAD_REQUEST).entity("Unable to deserialize input").build();
		}
		
		if (grouphosts.isEmpty()) {
			return Response.status(Status.BAD_REQUEST).entity("POST requires at least one input object").build();
		}
		int count = 0;
		for (GroupHostMapping ghm : grouphosts) {
			try {
				ps = conn.prepareStatement("select groupurn,fqdn from group_host where groupurn = ? and fqdn = ?");
				ps.setString(1,ghm.getGroupurn());
				ps.setString(2, ghm.getFqdn());
				if (ps != null) {
					rs = ps.executeQuery();
					if (rs == null || !rs.next()) {
						PreparedStatement ps2 = null;
						ps2 = conn.prepareStatement("insert into group_host values (?,?,?)");
						if (ps2 != null) {
							ps2.setString(1, ghm.getGroupurn());
							ps2.setString(2, ghm.getFqdn());
							ps2.setString(3, ghm.getOudn());
							ps2.executeUpdate();
							count += 1;
							ps2.close();
						}
					}
				} 
			} catch (Exception e) {
				// ignore exceptions during updates
			}
		}
		
		return Response.status(Status.ACCEPTED).entity("Created " + count + " new bindings").build();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@GET
	@Path("/dynamicgrouphosts")
	public Response handleDynamicGroupHostsGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<GroupHostMapping> hostmaps = new ArrayList<GroupHostMapping>();
		
		try {
			ps = conn.prepareStatement("select * from group_host");
			if (ps == null) {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database query failure").build();
			}
			
			rs = ps.executeQuery();
			
			while (rs != null && rs.next()) {
				GroupHostMapping ghm = new GroupHostMapping();
				ghm.setGroupurn(rs.getString("groupurn"));
				ghm.setFqdn(rs.getString("fqdn"));
				ghm.setOudn(rs.getString("ou"));
				hostmaps.add(ghm);
			}
			
			ps.close();
			if (rs != null) {
				rs.close();
			}
			
			if (! hostmaps.isEmpty()) {
				ObjectMapper om = new ObjectMapper();
				String json = om.writeValueAsString(hostmaps);
				return Response.status(Status.OK).entity(json.trim()).type("application/json").build();
			} else {
				return Response.status(Status.NOT_FOUND).entity("").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	// The /dynamicuserhosts endpoint handles authorization to 
	// access specific target FQDNs by specific users.  Note
	// that assigning dynamic user rights to a user does *not*
	// automatically assign the user application rights -- these
	// are atomic operations.  Aggregate operations are handled
	// in different endpoints.
	
	@DELETE
	@Path("/dynamicuserhosts/{eppn}/{fqdn}")
	public Response handleDynamicUserHostsDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("eppn") String eppn, @PathParam("fqdn") String fqdn) {
		
		// Given a user eppn and fqdn, remove the associated UserHostMapping
		
		PCApiConfig config = PCApiConfig.getInstance();
		Connection conn = null;
		PreparedStatement ps = null;
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database");
		}
		
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		try {
			ps = conn.prepareStatement("delete from explicit_hosts where eppn = ? and fqdn = ?");
			if (ps != null) {
				ps.setString(1, eppn);
				ps.setString(2,  fqdn);
				ps.executeUpdate();
				return Response.status(Status.OK).entity("Deleted").build();
			} else {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Deletion failed").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (ps != null) {
				try {
					ps.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@POST
	@Path("/dynamicuserhosts")
	public Response handleDynamicUserHostsPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		// Given a UserHostMapping, add it to the authorization set
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		// Authorization
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		try {
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<UserHostMapping> userhosts = new ArrayList<UserHostMapping>();
		
		if (entity == null || entity.equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("POST body missing").build();
		}
		
		// We accept either a single AccessUserEntry or an array of AccessUserEntry in input JSON
		
		ObjectMapper om = new ObjectMapper().enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
		try {
			userhosts = om.readValue(entity,new TypeReference<List<UserHostMapping>>(){});
		} catch (Exception e) {
			return Response.status(Status.BAD_REQUEST).entity("Unable to deserialize input").build();
		}
		
		if (userhosts.isEmpty()) {
			return Response.status(Status.BAD_REQUEST).entity("POST requires at least one input object").build();
		}
		int count = 0;
		for (UserHostMapping uhm : userhosts) {
			try {
				ps = conn.prepareStatement("select eppn,fqdn from explicit_hosts where eppn = ? and fqdn = ?");
				ps.setString(1,uhm.getEppn());
				ps.setString(2, uhm.getFqdn());
				if (ps != null) {
					rs = ps.executeQuery();
					if (rs == null || !rs.next()) {
						PreparedStatement ps2 = null;
						ps2 = conn.prepareStatement("insert into explicit_hosts values (?,?,?)");
						if (ps2 != null) {
							ps2.setString(1, uhm.getEppn());
							ps2.setString(2, uhm.getFqdn());
							ps2.setString(3, uhm.getOudn());
							ps2.executeUpdate();
							count += 1;
							ps2.close();
						}
					}
				} 
			} catch (Exception e) {
				// ignore exceptions during updates
			}
		}
		
		return Response.status(Status.ACCEPTED).entity("Created " + count + " new bindings").build();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@GET
	@Path("/dynamicuserhosts")
	public Response handleDynamicUserHostsGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<UserHostMapping> hostmaps = new ArrayList<UserHostMapping>();
		
		try {
			ps = conn.prepareStatement("select * from explicit_hosts");
			if (ps == null) {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database query failure").build();
			}
			
			rs = ps.executeQuery();
			
			while (rs != null && rs.next()) {
				UserHostMapping uhm = new UserHostMapping();
				uhm.setEppn(rs.getString("eppn"));
				uhm.setFqdn(rs.getString("fqdn"));
				uhm.setOudn(rs.getString("ou"));
				hostmaps.add(uhm);
			}
			
			ps.close();
			if (rs != null) {
				rs.close();
			}
			
			if (! hostmaps.isEmpty()) {
				ObjectMapper om = new ObjectMapper();
				String json = om.writeValueAsString(hostmaps);
				return Response.status(Status.OK).entity(json.trim()).type("application/json").build();
			} else {
				return Response.status(Status.NOT_FOUND).entity("").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	// 
	// The "/appentitlements" endpoint handles app authorizations
	// for entitlement values.  We don't use entitlements currently,
	// so this is unimplemented for the moment, but it can be added
	// on short notice at need.
	
	@DELETE
	@Path("/appentitlements/{urn}")
	public Response handleAppEntitlementsDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("urn") String urn) {
		return Response.status(Status.ACCEPTED).entity("Not implemented").build();
	}
	@POST
	@Path("/appentitlements")
	public Response handleAppEntitlementsPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		return Response.status(Status.ACCEPTED).entity("Not implemented").build();
	}
	@GET
	@Path("/appentitlements")
	public Response handleAppEntitlementsGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		return Response.status(Status.ACCEPTED).entity("Not implemented").build();
	}
	// The "/dausers" and "/dagroups" endpoints handle authorization
	// for users and groups (respectively) for Domain Admin access.
	// For now, these are noops -- domain admin access requires 
	// manual intervention by a human admin.  These can be expanded
	// easily enough at a later time.
	@DELETE
	@Path("/dagroups/{urn}")
	public Response handleDomainAdminGroupsDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("urn") String urn) {
		return Response.status(Status.ACCEPTED).entity("Not implemented").build();
	}
	@POST
	@Path("/dagroups")
	public Response handleDomainAdminGroupsPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		return Response.status(Status.ACCEPTED).entity("Not implemented").build();
	}
	@GET
	@Path("/dagroups")
	public Response handleDomainAdminGroupsGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		return Response.status(Status.ACCEPTED).entity("Not implemented").build();
	}
	@DELETE
	@Path("/dausers/{eppn}")
	public Response handleDomainAdminUsersDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("eppn") String eppn) {
		return Response.status(Status.ACCEPTED).entity("Not implemented").build();
	}
	@POST
	@Path("/dausers")
	public Response handleDomainAdminUsersPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		return Response.status(Status.ACCEPTED).entity("Not implemented").build();
	}
	@GET
	@Path("/dausers")
	public Response handleDomainAdminUsersGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		return Response.status(Status.ACCEPTED).entity("Not implemented").build();
	}
	// The "/appgroups" endpoint handles application group authZ
	// GET, POST, and DELETE are supported for list, add, and 
	// remove operations.
	// This pertains to group memberships that confer app access,
	// rather than explict user access rules (which are handled
	// by the /appusers/ endpoint)
	
	@DELETE
	@Path("/appgroups/{urn}")
	public Response handleAppGroupsDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("urn") String urn) {
		
		// Given a urn, remove the associated accessGroup
		
		PCApiConfig config = PCApiConfig.getInstance();
		Connection conn = null;
		PreparedStatement ps = null;
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database");
		}
		
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		try {
			ps = conn.prepareStatement("delete from access_groups where groupurn = ?");
			if (ps != null) {
				ps.setString(1, urn);
				ps.executeUpdate();
				return Response.status(Status.OK).entity("Deleted").build();
			} else {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Deletion failed").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (ps != null) {
				try {
					ps.close();
				} catch (Exception e) {
					//ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@POST
	@Path("/appgroups")
	public Response handleAppGroupsPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		// Given an AccessGroupEntry, add it to the authorization set
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		// Authorization
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		try {
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<AccessGroupEntry> appgroups = new ArrayList<AccessGroupEntry>();
		
		if (entity == null || entity.equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("POST body missing").build();
		}
		
		// We accept either a single AccessUserEntry or an array of AccessUserEntry in input JSON
		
		ObjectMapper om = new ObjectMapper().enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
		try {
			appgroups = om.readValue(entity,new TypeReference<List<AccessGroupEntry>>(){});
		} catch (Exception e) {
			return Response.status(Status.BAD_REQUEST).entity("Unable to deserialize input").build();
		}
		
		if (appgroups.isEmpty()) {
			return Response.status(Status.BAD_REQUEST).entity("POST requires at least one input object").build();
		}
		int count = 0;
		for (AccessGroupEntry age : appgroups) {
			try {
				ps = conn.prepareStatement("select groupurn from access_groups where groupurn = ?");
				ps.setString(1,age.getGroupurn());
				if (ps != null) {
					rs = ps.executeQuery();
					if (rs == null || !rs.next()) {
						PreparedStatement ps2 = null;
						ps2 = conn.prepareStatement("insert into access_groups values (?,?,?)");
						if (ps2 != null) {
							ps2.setString(1, age.getGroupurn());
							ps2.setString(2, age.getOu());
							ps2.setString(3, age.getType()==null?age.getType():"proconsul");
							ps2.executeUpdate();
							count += 1;
							ps2.close();
						}
					}
				} 
			} catch (Exception e) {
				// ignore exceptions during updates
			}
		}
		
		return Response.status(Status.ACCEPTED).entity("Created " + count + " new authorizations").build();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@GET
	@Path("/appgroups")
	public Response handleAppGroupsGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		//
		// List the groups conferring access rights (if any)
		//
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<AccessGroupEntry> appgroups = new ArrayList<AccessGroupEntry>();
		
		try {
			ps = conn.prepareStatement("select * from access_groups where type = 'proconsul'");
			if (ps == null) {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database query failure").build();
			}
			
			rs = ps.executeQuery();
			
			while (rs != null && rs.next()) {
				AccessGroupEntry age = new AccessGroupEntry();
				age.setGroupurn(rs.getString("groupurn"));
				age.setType(rs.getString("type"));
				appgroups.add(age);
			}
			
			ps.close();
			if (rs != null) {
				rs.close();
			}
			
			if (! appgroups.isEmpty()) {
				ObjectMapper om = new ObjectMapper();
				String json = om.writeValueAsString(appgroups);
				return Response.status(Status.OK).entity(json.trim()).type("application/json").build();
			} else {
				return Response.status(Status.NOT_FOUND).entity("").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	// The "/appusers" endpoint handles application user authZ
	// GET, POST, and DELETE are supported for list, add, and 
	// remove operations. 
	
	@DELETE
	@Path("/posixusers/{eppn}")
	public Response handlePosixUsersDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("eppn") String eppn) {
		
		// Given an eppn, remove the associated posixuser
		
		PCApiConfig config = PCApiConfig.getInstance();
		Connection conn = null;
		PreparedStatement ps = null;
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database");
		}
		
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		try {
			ps = conn.prepareStatement("delete from posixuser where uid = ?");
			if (ps != null) {
				ps.setString(1, eppn);
				ps.executeUpdate();
				return Response.status(Status.OK).entity("Deleted").build();
			} else {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Deletion failed").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@POST
	@Path("/posixusers")
	public Response handlePosixUsersGet(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		// Given an AccessUserEntry, add it to the authorization set
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		// Authorization
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		try {
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<PosixUser> posixusers = new ArrayList<PosixUser>();
		
		if (entity == null || entity.equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("POST body missing").build();
		}
		
		// We accept either a single AccessUserEntry or an array of AccessUserEntry in input JSON
		
		ObjectMapper om = new ObjectMapper().enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
		try {
			posixusers = om.readValue(entity,new TypeReference<List<PosixUser>>(){});
		} catch (Exception e) {
			return Response.status(Status.BAD_REQUEST).entity("Unable to deserialize input").build();
		}
		
		if (posixusers.isEmpty()) {
			return Response.status(Status.BAD_REQUEST).entity("POST requires at least one input object").build();
		}
		int count = 0;
		for (PosixUser pu : posixusers) {
			try {
				ps = conn.prepareStatement("select uid from posixuser where uid = ?");
				ps.setString(1,pu.getEppn());
				if (ps != null) {
					rs = ps.executeQuery();
					if (rs == null || !rs.next()) {
						PreparedStatement ps2 = null;
						ps2 = conn.prepareStatement("insert into posixuser values (?,?,?,?,?)");
						if (ps2 != null) {
							ps2.setString(1, pu.getEppn());
							ps2.setInt(2, pu.getUidnumber());
							ps2.setInt(3, pu.getGidnumber());
							ps2.setString(4, pu.getHomedirectory());
							ps2.setString(5, pu.getLoginshell());
							ps2.executeUpdate();
							count += 1;
							ps2.close();
						}
					}
				} 
			} catch (Exception e) {
				// ignore exceptions during updates
			}
		}
		
		return Response.status(Status.ACCEPTED).entity("Created " + count + " new authorizations").build();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}

	@GET
	@Path("/posixusers") 
	public Response handlePosixUsersGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		// Return a list of the users (by user identifier) authorized to 
		// use this instance of Proconsul.  This list is the explicit list
		// of *user* authorizations, not the list of *group* authorizations
		// (which is managed separately).
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		// Authorization
		if (!isAdmin(request, headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		// User is authorized
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<PosixUser> posixusers = new ArrayList<PosixUser>();
		
		try {
			ps = conn.prepareStatement("select * from posixuser");
			if (ps == null) {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database query failure").build();
			}
			
			rs = ps.executeQuery();
			
			while (rs != null && rs.next()) {
				PosixUser pu = new PosixUser();
				pu.setEppn(rs.getString("uid"));
				pu.setUidnumber(rs.getInt("uidnumber"));
				pu.setGidnumber(rs.getInt("gidnumber"));
				pu.setHomedirectory(rs.getString("homedirectory"));
				pu.setLoginshell(rs.getString("loginshell"));
				posixusers.add(pu);
			}
			
			ps.close();
			if (rs != null) {
				rs.close();
			}
			
			if (! posixusers.isEmpty()) {
				ObjectMapper om = new ObjectMapper();
				String json = om.writeValueAsString(posixusers);
				return Response.status(Status.OK).entity(json.trim()).type("application/json").build();
			} else {
				return Response.status(Status.NOT_FOUND).entity("").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	
	// The /usergroups endpoint manages mappings from users to 
	// AD group DNs for explicit group assignments for dynamic
	// user sessions.
	//
	// Note that these do not apply to static sessions, where it 
	// is presumed that the static user is pre-provisioned with 
	// all necessary group memberships.  Note also that the 
	// aggregate operations offered at other endpoints in this API
	// do not refer to user->group mappings here to determine what
	// groups to apply to static users on creation -- those must be 
	// specified explicitly at provisioning time.
	//
	
	@DELETE
	@Path("/usergroups/{eppn}/{groupdn}")
	public Response handleUserGroupsDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("eppn") String eppn, @PathParam("groupdn") String groupdn) {
		
		// Given a urn, remove the associated accessGroup
		
		PCApiConfig config = PCApiConfig.getInstance();
		Connection conn = null;
		PreparedStatement ps = null;
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database");
		}
		
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		try {
			ps = conn.prepareStatement("delete from explicit_groups where eppn = ? and groupdn = ?");
			if (ps != null) {
				ps.setString(1, eppn);
				ps.setString(2,  groupdn);
				ps.executeUpdate();
				return Response.status(Status.OK).entity("Deleted").build();
			} else {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Deletion failed").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (ps != null) {
				try {
					ps.close();
				} catch (Exception e) {
					//ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@POST
	@Path("/usergroups")
	public Response handleUserGroupsPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		// Given an AccessGroupEntry, add it to the authorization set
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		// Authorization
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		try {
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<UserGroupMapping> usergroups = new ArrayList<UserGroupMapping>();
		
		if (entity == null || entity.equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("POST body missing").build();
		}
		
		// We accept either a single UserGroupMapping or an array of them in input JSON
		
		ObjectMapper om = new ObjectMapper().enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
		try {
			usergroups = om.readValue(entity,new TypeReference<List<UserGroupMapping>>(){});
		} catch (Exception e) {
			return Response.status(Status.BAD_REQUEST).entity("Unable to deserialize input").build();
		}
		
		if (usergroups.isEmpty()) {
			return Response.status(Status.BAD_REQUEST).entity("POST requires at least one input object").build();
		}
		int count = 0;
		for (UserGroupMapping ugm : usergroups) {
			try {
				ps = conn.prepareStatement("select eppn from explicit_groups where eppn = ? and groupdn = ?");
				ps.setString(1,ugm.getEppn());
				ps.setString(2, ugm.getGroupdn());
				if (ps != null && ugm.getEppn() != null && ugm.getGroupdn() != null) {
					rs = ps.executeQuery();
					if (rs == null || !rs.next()) {
						PreparedStatement ps2 = null;
						ps2 = conn.prepareStatement("insert into explicit_groups values (?,?)");
						if (ps2 != null) {
							ps2.setString(1, ugm.getEppn());
							ps2.setString(2, ugm.getGroupdn());
							ps2.executeUpdate();
							count += 1;
							ps2.close();
						}
					}
				} 
			} catch (Exception e) {
				// ignore exceptions during updates
			}
		}
		
		return Response.status(Status.ACCEPTED).entity("Created " + count + " new authorizations").build();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@GET
	@Path("/usergroups")
	public Response handleUserGroupsGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		//
		// List the groups assigned to users (if any)
		//
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<UserGroupMapping> usergroups = new ArrayList<UserGroupMapping>();
		
		try {
			ps = conn.prepareStatement("select * from explicit_groups");
			if (ps == null) {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database query failure").build();
			}
			
			rs = ps.executeQuery();
			
			while (rs != null && rs.next()) {
				UserGroupMapping ugm = new UserGroupMapping();
				ugm.setEppn(rs.getString("eppn"));
				ugm.setGroupdn(rs.getString("groupdn"));
				usergroups.add(ugm);
			}
			
			ps.close();
			if (rs != null) {
				rs.close();
			}
			
			if (! usergroups.isEmpty()) {
				ObjectMapper om = new ObjectMapper();
				String json = om.writeValueAsString(usergroups);
				return Response.status(Status.OK).entity(json.trim()).type("application/json").build();
			} else {
				return Response.status(Status.NOT_FOUND).entity("").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	
	// The /groupgroups endpoint manages the equivalent maps from
	// isMemberOf groupURNs to group DNs in the AD for assignment
	// to dynamic users.  Essentially, members of a SAML group
	// will have their dynamic homonculi provisioned in the 
	// specified AD group(s).
	
	@DELETE
	@Path("/groupgroups/{urn}/{groupdn}")
	public Response handleGroupGroupsDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("urn") String urn, @PathParam("groupdn") String groupdn) {
		
		// Given a urn, remove the associated accessGroup
		
		PCApiConfig config = PCApiConfig.getInstance();
		Connection conn = null;
		PreparedStatement ps = null;
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database");
		}
		
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		try {
			ps = conn.prepareStatement("delete from group_group where groupurn = ? and groupdn = ?");
			if (ps != null) {
				ps.setString(1, urn);
				ps.setString(2,  groupdn);
				ps.executeUpdate();
				return Response.status(Status.OK).entity("Deleted").build();
			} else {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Deletion failed").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (ps != null) {
				try {
					ps.close();
				} catch (Exception e) {
					//ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@POST
	@Path("/groupgroups")
	public Response handleGroupGroupsPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		// Given an AccessGroupEntry, add it to the authorization set
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		// Authorization
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		try {
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<GroupGroupMapping> groupgroups = new ArrayList<GroupGroupMapping>();
		
		if (entity == null || entity.equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("POST body missing").build();
		}
		
		// We accept either a single UserGroupMapping or an array of them in input JSON
		
		ObjectMapper om = new ObjectMapper().enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
		try {
			groupgroups = om.readValue(entity,new TypeReference<List<GroupGroupMapping>>(){});
		} catch (Exception e) {
			return Response.status(Status.BAD_REQUEST).entity("Unable to deserialize input").build();
		}
		
		if (groupgroups.isEmpty()) {
			return Response.status(Status.BAD_REQUEST).entity("POST requires at least one input object").build();
		}
		int count = 0;
		for (GroupGroupMapping ggm : groupgroups) {
			try {
				ps = conn.prepareStatement("select groupurn from group_group where groupurn = ? and groupdn = ?");
				ps.setString(1,ggm.getGroupurn());
				ps.setString(2, ggm.getGroupdn());
				if (ps != null && ggm.getGroupurn() != null && ggm.getGroupdn() != null) {
					rs = ps.executeQuery();
					if (rs == null || !rs.next()) {
						PreparedStatement ps2 = null;
						ps2 = conn.prepareStatement("insert into group_group values (?,?)");
						if (ps2 != null) {
							ps2.setString(1, ggm.getGroupurn());
							ps2.setString(2, ggm.getGroupdn());
							ps2.executeUpdate();
							count += 1;
							ps2.close();
						}
					}
				} 
			} catch (Exception e) {
				// ignore exceptions during updates
			}
		}
		
		return Response.status(Status.ACCEPTED).entity("Created " + count + " new authorizations").build();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	@GET
	@Path("/groupgroups")
	public Response handleGroupGroupsGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		//
		// List the groups assigned to users (if any)
		//
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<GroupGroupMapping> groupgroups = new ArrayList<GroupGroupMapping>();
		
		try {
			ps = conn.prepareStatement("select * from group_group");
			if (ps == null) {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database query failure").build();
			}
			
			rs = ps.executeQuery();
			
			while (rs != null && rs.next()) {
				GroupGroupMapping ggm = new GroupGroupMapping();
				ggm.setGroupurn(rs.getString("groupurn"));
				ggm.setGroupdn(rs.getString("groupdn"));
				groupgroups.add(ggm);
			}
			
			ps.close();
			if (rs != null) {
				rs.close();
			}
			
			if (! groupgroups.isEmpty()) {
				ObjectMapper om = new ObjectMapper();
				String json = om.writeValueAsString(groupgroups);
				return Response.status(Status.OK).entity(json.trim()).type("application/json").build();
			} else {
				return Response.status(Status.NOT_FOUND).entity("").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	
	// The /posixusers endpoint manages POSIX user attributes
	// for application to dynamic homunculi.  
	//
	
	@DELETE
	@Path("/appusers/{eppn}")
	public Response handleAppUsersDelete(@Context HttpServletRequest request, @Context HttpHeaders headers, @PathParam("eppn") String eppn) {
		
		// Given an eppn, remove the associated accessUser
		
		PCApiConfig config = PCApiConfig.getInstance();
		Connection conn = null;
		PreparedStatement ps = null;
		
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database");
		}
		
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		try {
			ps = conn.prepareStatement("delete from access_user where eppn = ?");
			if (ps != null) {
				ps.setString(1, eppn);
				ps.executeUpdate();
				return Response.status(Status.OK).entity("Deleted").build();
			} else {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Deletion failed").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@POST
	@Path("/appusers")
	public Response handleAppUsersPost(@Context HttpServletRequest request, @Context HttpHeaders headers, String entity) {
		// Given an AccessUserEntry, add it to the authorization set
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		// Authorization
		if (!isAdmin(request,headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		try {
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<AccessUserEntry> appusers = new ArrayList<AccessUserEntry>();
		
		if (entity == null || entity.equals("")) {
			return Response.status(Status.BAD_REQUEST).entity("POST body missing").build();
		}
		
		// We accept either a single AccessUserEntry or an array of AccessUserEntry in input JSON
		
		ObjectMapper om = new ObjectMapper().enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
		try {
			appusers = om.readValue(entity,new TypeReference<List<AccessUserEntry>>(){});
		} catch (Exception e) {
			return Response.status(Status.BAD_REQUEST).entity("Unable to deserialize input").build();
		}
		
		if (appusers.isEmpty()) {
			return Response.status(Status.BAD_REQUEST).entity("POST requires at least one input object").build();
		}
		int count = 0;
		for (AccessUserEntry aue : appusers) {
			try {
				ps = conn.prepareStatement("select eppn from access_user where eppn = ?");
				ps.setString(1,aue.getEppn());
				if (ps != null) {
					rs = ps.executeQuery();
					if (rs == null || !rs.next()) {
						PreparedStatement ps2 = null;
						ps2 = conn.prepareStatement("insert into access_user values (?,?)");
						if (ps2 != null) {
							ps2.setString(1, aue.getEppn());
							ps2.setString(2, aue.getType());
							ps2.executeUpdate();
							count += 1;
							ps2.close();
						}
					}
				} 
			} catch (Exception e) {
				// ignore exceptions during updates
			}
		}
		
		return Response.status(Status.ACCEPTED).entity("Created " + count + " new authorizations").build();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}

	@GET
	@Path("/appusers") 
	public Response handleAppUsersGet(@Context HttpServletRequest request, @Context HttpHeaders headers) {
		// Return a list of the users (by user identifier) authorized to 
		// use this instance of Proconsul.  This list is the explicit list
		// of *user* authorizations, not the list of *group* authorizations
		// (which is managed separately).
		
		PCApiConfig config = PCApiConfig.getInstance();
		
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		
		// Authorization
		if (!isAdmin(request, headers)) {
			return Response.status(Status.FORBIDDEN).entity("You are not authorized to perform this operation").build();
		}
		
		// User is authorized
		
		try {
			conn = DatabaseConnectionFactory.getPCApiDBConnection();
		} catch (Exception e) {
			throw new RuntimeException("Failed connecting to database: " + e.getMessage());
		}
		if (conn == null) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database connection failed").build();
		}
		
		// Connected
		
		ArrayList<AccessUserEntry> appusers = new ArrayList<AccessUserEntry>();
		
		try {
			ps = conn.prepareStatement("select * from access_user where type = 'proconsul'");
			if (ps == null) {
				return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Database query failure").build();
			}
			
			rs = ps.executeQuery();
			
			while (rs != null && rs.next()) {
				AccessUserEntry aue = new AccessUserEntry();
				aue.setEppn(rs.getString("eppn"));
				aue.setType(rs.getString("type"));
				appusers.add(aue);
			}
			
			ps.close();
			if (rs != null) {
				rs.close();
			}
			
			if (! appusers.isEmpty()) {
				ObjectMapper om = new ObjectMapper();
				String json = om.writeValueAsString(appusers);
				return Response.status(Status.OK).entity(json.trim()).type("application/json").build();
			} else {
				return Response.status(Status.NOT_FOUND).entity("").build();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (Exception e) {
					// ignore
				}
			}
			if (ps != null) {
				try {
					ps.close();
				} catch(Exception e) {
					// ignore
				}
			}
			if (conn != null) {
				try {
					conn.close();
				} catch (Exception e) {
					// ignore
				}
			}
		}
	}
	
	// Here begin the aggregated API endpoints for handling 
	// combined operations.  
	//
	// Where the above endpoints expose atomic Proconsul 
	// specific operations (database CRUD, essentially), the
	// following endpoints provide for goal-oriented operations.
	//
	// We add a "provisioning" concept, and consider creating,  
	// modifying, and deleting "provisioned" static and 
	// dynamic users.  
	//
	// Provisioning a static user, for example, amounts to ensuring
	// a number of things:
	//
	// * the eppn is granted app access
	// * the static target user exists in the AD
	// * the static target user has minimal AD rights
	// * the static mapping from eppn to fqdn and targetuser exists
	//
	// Deprovisioning (deleting) as static user amounts to reversing
	// that (to an extent):
	//
	// * the static mapping is removed
	//
	// Modifying static mappings may entail adding properties
	// to the static targetuser (group memberships and/or POSIX
	// attributes).
	
	
}