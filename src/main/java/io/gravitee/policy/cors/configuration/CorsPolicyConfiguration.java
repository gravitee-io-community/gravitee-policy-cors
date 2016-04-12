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
package io.gravitee.policy.cors.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.policy.api.PolicyConfiguration;
import io.gravitee.policy.cors.utils.CaseInsensitiveHashSet;

import java.util.Set;

/**
 * @author David BRASSELY (david at gravitee.io)
 * @author GraviteeSource Team
 */
@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class CorsPolicyConfiguration implements PolicyConfiguration {

    // Access-Control-Allow-Origin
    @JsonProperty("accessControlAllowOrigin")
    private String accessControlAllowOrigin;

    // Access-Control-Expose-Headers
    @JsonProperty("accessControlExposeHeaders")
    @JsonDeserialize(as = CaseInsensitiveHashSet.class)
    private Set<String> accessControlExposeHeaders = new CaseInsensitiveHashSet();

    // Access-Control-Max-Age
    @JsonProperty("accessControlMaxAge")
    private int accessControlMaxAge = -1;

    // Access-Control-Allow-Credentials
    @JsonProperty("accessControlAllowCredentials")
    private boolean accessControlAllowCredentials;

    // Access-Control-Allow-Methods
    @JsonProperty("accessControlAllowMethods")
    @JsonDeserialize(as = CaseInsensitiveHashSet.class)
    private Set<String> accessControlAllowMethods = new CaseInsensitiveHashSet();

    // Access-Control-Allow-Headers
    @JsonProperty("accessControlAllowHeaders")
    @JsonDeserialize(as = CaseInsensitiveHashSet.class)
    private Set<String> accessControlAllowHeaders = new CaseInsensitiveHashSet();

    private int corsErrorStatusCode = HttpStatusCode.BAD_REQUEST_400;

    public boolean isAccessControlAllowCredentials() {
        return accessControlAllowCredentials;
    }

    public void setAccessControlAllowCredentials(boolean accessControlAllowCredentials) {
        this.accessControlAllowCredentials = accessControlAllowCredentials;
    }

    public Set<String> getAccessControlAllowHeaders() {
        return accessControlAllowHeaders;
    }

    public void setAccessControlAllowHeaders(Set<String> accessControlAllowHeaders) {
        this.accessControlAllowHeaders = accessControlAllowHeaders;
    }

    public Set<String> getAccessControlAllowMethods() {
        return accessControlAllowMethods;
    }

    public void setAccessControlAllowMethods(Set<String> accessControlAllowMethods) {
        this.accessControlAllowMethods = accessControlAllowMethods;
    }

    public String getAccessControlAllowOrigin() {
        return accessControlAllowOrigin;
    }

    public void setAccessControlAllowOrigin(String accessControlAllowOrigin) {
        this.accessControlAllowOrigin = accessControlAllowOrigin;
    }

    public Set<String> getAccessControlExposeHeaders() {
        return accessControlExposeHeaders;
    }

    public void setAccessControlExposeHeaders(Set<String> accessControlExposeHeaders) {
        this.accessControlExposeHeaders = accessControlExposeHeaders;
    }

    public int getAccessControlMaxAge() {
        return accessControlMaxAge;
    }

    public void setAccessControlMaxAge(int accessControlMaxAge) {
        this.accessControlMaxAge = accessControlMaxAge;
    }

    public int getCorsErrorStatusCode() {
        return corsErrorStatusCode;
    }

    public void setCorsErrorStatusCode(int corsErrorStatusCode) {
        this.corsErrorStatusCode = corsErrorStatusCode;
    }
}
