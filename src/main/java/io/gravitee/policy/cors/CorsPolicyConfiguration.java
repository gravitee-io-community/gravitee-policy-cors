/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.cors;

import io.gravitee.gateway.api.policy.PolicyConfiguration;

/**
 * TODO Handle specific header types to avoid only using String values
 *
 * @author Aurélien Bourdon (aurelien.bourdon at gmail.com)
 */
@SuppressWarnings("unused")
public class CorsPolicyConfiguration implements PolicyConfiguration {

    private CorsPolicyConfigurationProperty<String> accessControlAllowOrigin;

    private CorsPolicyConfigurationProperty<String> accessControlAllowCredentials;

    private CorsPolicyConfigurationProperty<String> accessControlExposeHeaders;

    private CorsPolicyConfigurationProperty<String> accessControlMaxAge;

    private CorsPolicyConfigurationProperty<String> accessControlAllowMethods;

    private CorsPolicyConfigurationProperty<String> accessControlAllowHeaders;

    public CorsPolicyConfigurationProperty<String> getAccessControlAllowOrigin() {
        return accessControlAllowOrigin;
    }

    public void setAccessControlAllowOrigin(CorsPolicyConfigurationProperty<String> accessControlAllowOrigin) {
        this.accessControlAllowOrigin = accessControlAllowOrigin;
    }

    public CorsPolicyConfigurationProperty<String> getAccessControlAllowCredentials() {
        return accessControlAllowCredentials;
    }

    public void setAccessControlAllowCredentials(CorsPolicyConfigurationProperty<String> accessControlAllowCredentials) {
        this.accessControlAllowCredentials = accessControlAllowCredentials;
    }

    public CorsPolicyConfigurationProperty<String> getAccessControlExposeHeaders() {
        return accessControlExposeHeaders;
    }

    public void setAccessControlExposeHeaders(CorsPolicyConfigurationProperty<String> accessControlExposeHeaders) {
        this.accessControlExposeHeaders = accessControlExposeHeaders;
    }

    public CorsPolicyConfigurationProperty<String> getAccessControlMaxAge() {
        return accessControlMaxAge;
    }

    public void setAccessControlMaxAge(CorsPolicyConfigurationProperty<String> accessControlMaxAge) {
        this.accessControlMaxAge = accessControlMaxAge;
    }

    public CorsPolicyConfigurationProperty<String> getAccessControlAllowMethods() {
        return accessControlAllowMethods;
    }

    public void setAccessControlAllowMethods(CorsPolicyConfigurationProperty<String> accessControlAllowMethods) {
        this.accessControlAllowMethods = accessControlAllowMethods;
    }

    public CorsPolicyConfigurationProperty<String> getAccessControlAllowHeaders() {
        return accessControlAllowHeaders;
    }

    public void setAccessControlAllowHeaders(CorsPolicyConfigurationProperty<String> accessControlAllowHeaders) {
        this.accessControlAllowHeaders = accessControlAllowHeaders;
    }
}
