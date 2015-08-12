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
 * @author abourdon
 */
@SuppressWarnings("unused")
public class CorsPolicyConfiguration implements PolicyConfiguration {

    private String accessControlAllowOrigin;

    private boolean overrideAccessControlAllowOrigin;

    private String accessControlAllowCredentials;

    private boolean overrideAccessControlAllowCredentials;

    private String accessControlExposeHeaders;

    private boolean overrideAccessControlExposeHeaders;

    private String accessControlMaxAge;

    private boolean overrideAccessControlMaxAge;

    private String accessControlAllowMethods;

    private boolean overrideAccessControlAllowMethods;

    private String accessControlAllowHeaders;

    private boolean overrideAccessControlAllowHeaders;

    public String getAccessControlAllowOrigin() {
        return accessControlAllowOrigin;
    }

    public boolean isOverrideAccessControlAllowOrigin() {
        return overrideAccessControlAllowOrigin;
    }

    public String getAccessControlAllowCredentials() {
        return accessControlAllowCredentials;
    }

    public boolean isOverrideAccessControlAllowCredentials() {
        return overrideAccessControlAllowCredentials;
    }

    public String getAccessControlExposeHeaders() {
        return accessControlExposeHeaders;
    }

    public boolean isOverrideAccessControlExposeHeaders() {
        return overrideAccessControlExposeHeaders;
    }

    public String getAccessControlMaxAge() {
        return accessControlMaxAge;
    }

    public boolean isOverrideAccessControlMaxAge() {
        return overrideAccessControlMaxAge;
    }

    public String getAccessControlAllowMethods() {
        return accessControlAllowMethods;
    }

    public boolean isOverrideAccessControlAllowMethods() {
        return overrideAccessControlAllowMethods;
    }

    public String getAccessControlAllowHeaders() {
        return accessControlAllowHeaders;
    }

    public boolean isOverrideAccessControlAllowHeaders() {
        return overrideAccessControlAllowHeaders;
    }

}
