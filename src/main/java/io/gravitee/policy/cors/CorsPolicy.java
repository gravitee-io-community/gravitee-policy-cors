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

import io.gravitee.common.http.HttpHeader;
import io.gravitee.common.http.HttpMethod;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.policy.PolicyChain;
import io.gravitee.gateway.api.policy.annotations.OnResponse;

/**
 * @author abourdon
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

    private void applyAccessControlAllowOrigin(Response response) {
        if (isActiveConfiguration(configuration.getAccessControlAllowOrigin())) {
            if (!response.headers().containsKey(HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN.toString()) || configuration.isOverrideAccessControlAllowOrigin()) {
                response.headers().put(HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN.toString(), configuration.getAccessControlAllowOrigin());
            }
        }
    }

    private void applyAccessControlAllowCredentials(Response response) {
        if (isActiveConfiguration(configuration.getAccessControlAllowCredentials())) {
            if (!response.headers().containsKey(HttpHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS.toString()) || configuration.isOverrideAccessControlAllowCredentials()) {
                response.headers().put(HttpHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS.toString(), configuration.getAccessControlAllowCredentials());
            }
        }
    }

    private void applyAccessControlExposeHeaders(Response response) {
        if (isActiveConfiguration(configuration.getAccessControlExposeHeaders())) {
            if (!response.headers().containsKey(HttpHeader.ACCESS_CONTROL_EXPOSE_HEADERS.toString()) || configuration.isOverrideAccessControlExposeHeaders()) {
                response.headers().put(HttpHeader.ACCESS_CONTROL_EXPOSE_HEADERS.toString(), configuration.getAccessControlExposeHeaders());
            }
        }
    }

    private void applyAccessControlMaxAge(Response response) {
        if (isActiveConfiguration(configuration.getAccessControlMaxAge())) {
            if (!response.headers().containsKey(HttpHeader.ACCESS_CONTROL_MAX_AGE.toString()) || configuration.isOverrideAccessControlMaxAge()) {
                response.headers().put(HttpHeader.ACCESS_CONTROL_MAX_AGE.toString(), configuration.getAccessControlMaxAge());
            }
        }
    }

    private void applyAccessControlAllowMethods(Response response) {
        if (isActiveConfiguration(configuration.getAccessControlAllowMethods())) {
            if (!response.headers().containsKey(HttpHeader.ACCESS_CONTROL_ALLOW_METHODS.toString()) || configuration.isOverrideAccessControlAllowMethods()) {
                response.headers().put(HttpHeader.ACCESS_CONTROL_ALLOW_METHODS.toString(), configuration.getAccessControlAllowMethods());
            }
        }
    }

    private void applyAccessControlAllowHeaders(Response response) {
        if (isActiveConfiguration(configuration.getAccessControlAllowHeaders())) {
            if (!response.headers().containsKey(HttpHeader.ACCESS_CONTROL_ALLOW_HEADERS.toString()) || configuration.isOverrideAccessControlAllowHeaders()) {
                response.headers().put(HttpHeader.ACCESS_CONTROL_ALLOW_HEADERS.toString(), configuration.getAccessControlAllowHeaders());
            }
        }
    }

}
