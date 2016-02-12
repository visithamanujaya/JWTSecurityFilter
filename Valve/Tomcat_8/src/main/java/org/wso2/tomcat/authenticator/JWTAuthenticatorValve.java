/*
*  Copyright (c) 2005-2011, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/
package org.wso2.tomcat.authenticator;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.tomcat.util.res.StringManager;
import org.wso2.tomcat.JSON.JSONObject;
import org.wso2.tomcat.JSON.parser.JSONParser;
import org.wso2.tomcat.JSON.parser.ParseException;

import javax.servlet.ServletException;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Valve takes the request and forward it to the next valve if the principal exist else vale read
 * the JWT token and if the token available it reads JWT token and create a eneric principal using
 * the data available in the JWT token, then put it to the request and forward.
 */
public class JWTAuthenticatorValve extends ValveBase {
    private static final String JWT_TOKEN_SUBJECT = "sub";
    private static final String JWT_TOKEN_NAME = "x-jwt-assertion";
    private static final String JWT_TOKEN_USER_ROLES = "http://wso2.org/claims/role";
    private static final StringManager sm = StringManager.getManager(
            "org.apache.catalina.authenticator");

    /**
     * clsss constructor without arguments
     */
    public JWTAuthenticatorValve() {
        super(true);
    }

    public void invoke(Request request, Response response) throws IOException, ServletException {

        if (request.getUserPrincipal() != null) {
            if (this.containerLog.isDebugEnabled()) {
                this.containerLog.debug(sm.getString("singleSignOn.debug.hasPrincipal",
                                                     new Object[]{request.getUserPrincipal()
                                                             .getName()}));
            }
            this.getNext().invoke(request, response);
        } else {
            if (this.containerLog.isDebugEnabled()) {
                this.containerLog.debug(sm.getString("singleSignOn.debug.noPrincipal.checkJWT"));
            }
            String jwtHeader = request.getHeader(JWT_TOKEN_NAME);
            Principal principal = request.getUserPrincipal();

            if (jwtHeader == null) {
                if (this.containerLog.isDebugEnabled()) {
                    this.containerLog.debug(sm.getString("singleSignOn.debug.JWTHeaderNotFound"));
                }
                this.getNext().invoke(request, response);
            } else {

                if (principal == null) {
                    String payLoad = jwtHeaderPayloadDecode(jwtHeader);
                    if (payLoad != null) {
                        JSONObject payloadObject = jsonObjectConverter(payLoad);
                        List<String> roleList = getRoleList(payloadObject);
                        String userName = (String) payloadObject.get(JWT_TOKEN_SUBJECT);
                        JWTGenericPrincipal jwtGenericPrincipal = new JWTGenericPrincipal(userName,
                                                                                          "",
                                                                                          roleList,
                                                                                          principal);
                        request.setUserPrincipal(jwtGenericPrincipal);
                        request.setAuthType("Form");
                        this.getNext().invoke(request, response);

                    } else {
                        this.getNext().invoke(request, response);
                    }

                } else {
                    this.getNext().invoke(request, response);
                }
            }
        }
    }

    private String jwtHeaderPayloadDecode(String jwtHeader) {
        String[] jwtArray = jwtHeader.split("\\.");
        if (jwtArray.length != 3) {
            return null;
        }
        byte[] decodedPayload = DatatypeConverter.parseBase64Binary(jwtArray[1]);
        String payloadString = new String(decodedPayload);
        return payloadString;
    }

    private JSONObject jsonObjectConverter(String payloadString) {
        JSONObject payLoad = null;
        try {
            payLoad = (JSONObject) new JSONParser().parse(payloadString);
            return payLoad;
        } catch (ParseException e) {
            return payLoad;
        }
    }

    private List<String> getRoleList(JSONObject jsonObjectPayload) {
        String roles = (String) jsonObjectPayload.get(JWT_TOKEN_USER_ROLES);
        List<String> rolesList;
        if (roles != null) {
            rolesList = new ArrayList<String>(Arrays.asList(roles.split(",")));
            return rolesList;
        } else {
            rolesList = Collections.emptyList();
            return rolesList;
        }
    }
}
