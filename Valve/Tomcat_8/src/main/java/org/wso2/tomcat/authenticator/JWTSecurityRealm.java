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


import org.apache.catalina.realm.RealmBase;

import java.security.Principal;

public class JWTSecurityRealm extends RealmBase{

    /** The Constant NAME. */
    protected static final String NAME = "wso2.apache.JWTRealm/1.0";

    /*
     * (non-Javadoc)
     * @see org.apache.catalina.realm.RealmBase#getName()
     */
    @Override
    protected String getName() {
        return JWTSecurityRealm.NAME;
    }

    /*
     * (non-Javadoc)
     * @see org.apache.catalina.realm.RealmBase#getPassword(java.lang.String)
     */
    @Override
    protected String getPassword(final String value) {
        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.apache.catalina.realm.RealmBase#getPrincipal(java.lang.String)
     */
    @Override
    protected Principal getPrincipal(final String value) {
        return null;
    }

}