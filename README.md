JWT Security Filter Readme


This is a JWT Security filter which can be use to avoid second login page for AppManager users for j2ee secured web applications.
Here we are going to show you how to apply this filter to an application with an example.

Prerequisites 

JWTSecurityFilter source or jar file
Download from - https://github.com/visithamanujaya/JWTSecurityFilter/tree/master
Sample web application 
Download from - https://github.com/visithamanujaya/Sample_WebApp_For_JWT_Security_Filter
Simple JSON library 1.1.1
Download from - http://mvnrepository.com/artifact/com.googlecode.json-simple/json-simple/1.1.1
Install AppManager
Install Tomcat

Configurations

Step – 1	

	Build the web application using maven and deploy it in tomcat.

Step – 2
	
	Build the Filter souse and create JWTSecurityFilter.jar 

Step – 3
  
 	Copy  JWTSecurityFilter.jar and json-simple-1.1.1.jar to the
	TOMCAT_HOME /webapps/Sample_WebApp/WEB-INF/lib

Step – 4	
	
	Create CustomData.xml file in TOMCAT_HOME /webapps/Sample_WebApp/WEB-INF/
	and define security constraints which are defined in web.xml file of the application. 
	(already created sample customdata.xml can be found in source of the filter.)

E.g

A security constraint defined in web.xml
```<xml>
```

	 <security-constraint>
		<display-name>SecurityConstraint</display-name>
		<web-resource-collection>
		    <web-resource-name>WRCollection</web-resource-name>
		    <url-pattern>/marketing.jsp</url-pattern>
		</web-resource-collection>
		<auth-constraint>
		    <role-name>admin</role-name>
		    <role-name>MarketingOfficer</role-name>
		</auth-constraint>
		<user-data-constraint>
		    <transport-guarantee>NONE</transport-guarantee>
		</user-data-constraint>
	 </security-constraint>

How the above should be defined in CustomData.xml, here you have to consider only about url pattern and the user role.

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<customData id="1">
    <securityData>

	 <authParam>
            <roleName>admin</roleName>
 	    <roleName>Marketing</roleName>
            <urlPattern>/marketing.jsp</urlPattern>
        </authParam>
    </securityData>

</customData>


Step – 5

	Delete all security constraints and login configurations from web.xml


Step – 6

	Go to AppManager and create corresponding users and their roles then deploy the app from AppManager.

Step – 7

	Log with different users and test the application.
