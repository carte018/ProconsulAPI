package edu.duke.oit.proconsulapi;

import java.sql.Connection;
import java.sql.SQLException;


public class DatabaseConnectionFactory {

	public static Connection getPCApiDBConnection() throws SQLException {
		return PCApiDBConnection.getInstance().getConnection();
		
	}
}
