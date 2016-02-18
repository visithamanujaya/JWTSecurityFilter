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

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Valve takes the request and forward it to the next valve if the principal exist else valve read the JWT token and if
 * the token available it reads JWT token and create a generic principal using the data available in the JWT token, then
 * put it to the request and forward.
 */
public class JWTAuthenticatorValve extends ValveBase {
    private static final String JWT_TOKEN_SUBJECT = "sub";
    private static final String JWT_TOKEN_NAME = "x-jwt-assertion";
    private static final String JWT_TOKEN_USER_ROLES = "http://wso2.org/claims/role";
    private static final StringManager sm = StringManager.getManager(
            "org.apache.catalina.authenticator");
    final String TRUST_STORE_PATH =
            "/home/visitha/WAT/AppManager/wso2appm-1.2.0-SNAPSHOT/repository/resources/security/client-truststore.jks";
    final String TRUST_STORE_PASSWORD = "wso2carbon";
    protected String alias = "";
    private SimpleJWTProcessor simpleJWTProcessor = new SimpleJWTProcessor();

    public JWTAuthenticatorValve() {
        super(true);
    }

    public void invoke(Request request, Response response) throws IOException, ServletException {
        if (request.getUserPrincipal() == null) {
            if (this.containerLog.isDebugEnabled()) {
                this.containerLog.debug(sm.getString("singleSignOn.debug.noPrincipal.checkJWT"));
            }

            String jwtToken = request.getHeader(JWT_TOKEN_NAME);
            if (jwtToken != null) {
                if (simpleJWTProcessor.isValid(jwtToken, TRUST_STORE_PATH, TRUST_STORE_PASSWORD, alias)) {
                    String payLoad = simpleJWTProcessor.getjwtPayloadDecode(simpleJWTProcessor.jwtPartitions(
                            jwtToken));
                    if (payLoad != null) {
                        JSONObject payloadObject = simpleJWTProcessor.jsonObjectConverter(payLoad);
                        List<String> roleList = getRoleList(payloadObject);
                        String userName = (String) payloadObject.get(JWT_TOKEN_SUBJECT);
                        JWTGenericPrincipal jwtGenericPrincipal = new JWTGenericPrincipal(userName, "", roleList);
                        request.setUserPrincipal(jwtGenericPrincipal);
                        request.setAuthType("Form");
                    }
                }
            } else {
                if (this.containerLog.isDebugEnabled()) {
                    this.containerLog.debug(sm.getString("singleSignOn.debug.JWTHeaderNotFound"));
                }
            }
        } else {
            if (this.containerLog.isDebugEnabled()) {
                this.containerLog.debug(sm.getString("singleSignOn.debug.hasPrincipal",
                                                     new Object[]{request.getUserPrincipal()
                                                             .getName()}));
            }
        }
        this.getNext().invoke(request, response);
    }

    private List<String> getRoleList(JSONObject jsonObjectPayload) {
        String roles = (String) jsonObjectPayload.get(JWT_TOKEN_USER_ROLES);
        List<String> rolesList;
        if (roles != null) {
            rolesList = new ArrayList<String>(Arrays.asList(roles.split(",")));
        } else {
            rolesList = Collections.emptyList();
        }
        return rolesList;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
}
