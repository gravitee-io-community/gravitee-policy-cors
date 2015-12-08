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

import io.gravitee.common.http.GraviteeHttpHeader;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpMethod;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.annotations.OnResponse;

/**
 * @author Aurélien Bourdon (aurelien.bourdon at gmail.com)
 */
@SuppressWarnings("unused")
public class CorsPolicy {

    /**
     * The associated configuration to this Cors Policy
     */
    private CorsPolicyConfiguration configuration;

    /**
     * Create a new Cors Policy instance based on its associated configuration
     *
     * @param configuration the associated configuration to the new Cors Policy instance
     */
    public CorsPolicy(CorsPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Check if the given configuration name is active, i.e., if configuration is not <code>null</code>.
     *
     * @param configuration the configuration to check if active
     * @return <code>true</code> if configuration is active, <code>false</code> otherwise
     */
    private static boolean isActiveConfiguration(Object configuration) {
        return configuration != null;
    }

    @OnResponse
    public void onResponse(Request request, Response response, PolicyChain policyChain) {
        if (request.method() == HttpMethod.OPTIONS) {
            applyAccessControlAllowOrigin(response);
            applyAccessControlAllowCredentials(response);
            applyAccessControlExposeHeaders(response);
            applyAccessControlMaxAge(response);
            applyAccessControlAllowMethods(response);
            applyAccessControlAllowHeaders(response);
        }

        policyChain.doNext(request, response);
    }

    private static void updateHeader(Response response, String name, String value) {
        // If value is null, then we have to remove header
        if (value == null) {
            response.headers().remove(name);
        }
        // Else we have to update its value
        else {
            response.headers().set(name, value);
        }
    }

    private void applyAccessControlAllowOrigin(Response response) {
        if (configuration.getAccessControlAllowOrigin().isEnabled()) {
            if (!response.headers().containsKey(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN) || configuration.getAccessControlAllowOrigin().isOverridden()) {
                updateHeader(response, HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, configuration.getAccessControlAllowOrigin().getValue());
            }
        }
    }

    private void applyAccessControlAllowCredentials(Response response) {
        if (configuration.getAccessControlAllowCredentials().isEnabled()) {
            if (!response.headers().containsKey(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS) || configuration.getAccessControlAllowCredentials().isOverridden()) {
                updateHeader(response, HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, configuration.getAccessControlAllowCredentials().getValue());
            }
        }
    }

    private void applyAccessControlExposeHeaders(Response response) {
        if (configuration.getAccessControlExposeHeaders().isEnabled()) {
            if (!response.headers().containsKey(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS) || configuration.getAccessControlExposeHeaders().isOverridden()) {
                updateHeader(response, HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, configuration.getAccessControlExposeHeaders().getValue());
            }
        }
    }

    private void applyAccessControlMaxAge(Response response) {
        if (configuration.getAccessControlMaxAge().isEnabled()) {
            if (!response.headers().containsKey(HttpHeaders.ACCESS_CONTROL_MAX_AGE) || configuration.getAccessControlMaxAge().isOverridden()) {
                updateHeader(response, HttpHeaders.ACCESS_CONTROL_MAX_AGE, configuration.getAccessControlMaxAge().getValue());
            }
        }
    }

    private void applyAccessControlAllowMethods(Response response) {
        if (configuration.getAccessControlAllowMethods().isEnabled()) {
            if (!response.headers().containsKey(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS) || configuration.getAccessControlAllowMethods().isOverridden()) {
                updateHeader(response, HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, configuration.getAccessControlAllowMethods().getValue());
            }
        }
    }

    private void applyAccessControlAllowHeaders(Response response) {
        if (configuration.getAccessControlAllowHeaders().isEnabled()) {
            // Create new allowed headers by adding...
            StringBuilder allowedHeaders = new StringBuilder();

            // ... Configured ones if necessary
            if (!response.headers().containsKey(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS) || configuration.getAccessControlAllowHeaders().isOverridden()) {
                if (configuration.getAccessControlAllowHeaders().getValue() != null) {
                    allowedHeaders.append(configuration.getAccessControlAllowHeaders().getValue());
                }
            }
            // ... Or by adding current allowed headers
            else if (response.headers().containsKey(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS)) {
                allowedHeaders.append(response.headers().getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS));
            }

            // ... And The X-Gravitee-Api-Key header
            if (allowedHeaders.length() != 0) {
                allowedHeaders.append(", ");
            }
            allowedHeaders.append(GraviteeHttpHeader.X_GRAVITEE_API_KEY);

            // Finally, replace old allowed headers by new computed ones
            response.headers().set(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, allowedHeaders.toString());
        }
    }

}
