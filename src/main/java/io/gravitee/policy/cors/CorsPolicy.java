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

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpMethod;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Invoker;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.api.proxy.ProxyConnection;
import io.gravitee.gateway.api.proxy.ProxyResponse;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.api.annotations.OnResponse;
import io.gravitee.policy.cors.configuration.CorsPolicyConfiguration;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@SuppressWarnings("unused")
public class CorsPolicy {

    private final static String ALLOW_ORIGIN_PUBLIC_WILDCARD = "*";

    private final static String JOINER_CHAR_SEQUENCE = ", ";

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

    @OnResponse
    public void onResponse(Request request, Response response, PolicyChain policyChain) {
        if (! isPreflightRequest(request)) {
            if (configuration.getAccessControlExposeHeaders() != null && ! configuration.getAccessControlExposeHeaders().isEmpty()) {
                response.headers().set(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS,
                        String.join(JOINER_CHAR_SEQUENCE, configuration.getAccessControlExposeHeaders()));
            }
        } else {
            response.headers().set(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                    String.join(JOINER_CHAR_SEQUENCE, configuration.getAccessControlAllowHeaders()));

            response.headers().set(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                    configuration.getAccessControlAllowMethods()
                            .stream()
                            .map(String::toUpperCase)
                            .collect(Collectors.joining(JOINER_CHAR_SEQUENCE)));

            if (configuration.getAccessControlMaxAge() > -1) {
                response.headers().set(HttpHeaders.ACCESS_CONTROL_MAX_AGE,
                        Integer.toString(configuration.getAccessControlMaxAge()));
            }
        }

        if (configuration.isAccessControlAllowCredentials()) {
            response.headers().set(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    Boolean.TRUE.toString());
            response.headers().set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
                    request.headers().getFirst(HttpHeaders.ORIGIN));
        } else {
            response.headers().set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, ALLOW_ORIGIN_PUBLIC_WILDCARD);
        }

        policyChain.doNext(request, response);
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        if (isPreflightRequest(request)) {
            // Update invoker to skip remote call
            executionContext.setAttribute(ExecutionContext.ATTR_INVOKER, new PreflightInvoker(request));
        }

        policyChain.doNext(request, response);
    }

    private boolean isOriginAllowed(String origin) {
        return origin.contains(ALLOW_ORIGIN_PUBLIC_WILDCARD) || origin.contains(origin);
    }

    boolean isRequestHeadersValid(String accessControlRequestHeaders) {
        return isRequestValid(accessControlRequestHeaders, configuration.getAccessControlAllowHeaders(), false);
    }

    boolean isRequestMethodsValid(String accessControlRequestMethods) {
        return isRequestValid(accessControlRequestMethods, configuration.getAccessControlAllowMethods(), true);
    }

    private boolean isRequestValid(String incoming, Set<String> configuredValues, boolean required) {
        String [] inputs = splitAndTrim(incoming, ",");
        if ((inputs == null || (inputs.length == 1 && inputs[0].isEmpty()))) {
            return true;
        }
        return (inputs == null && (configuredValues == null || configuredValues.isEmpty())) ||
                (inputs != null && containsAll(configuredValues, inputs));
    }

    private boolean isPreflightRequest(Request request) {
        String originHeader = request.headers().getFirst(HttpHeaders.ORIGIN);
        String accessControlRequestMethod = request.headers().getFirst(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD);
        return request.method() == HttpMethod.OPTIONS &&
                originHeader != null &&
                accessControlRequestMethod != null;
    }

    private static String[] splitAndTrim(String value, String regex) {
        if (value == null)
            return null;

        String [] values = value.split(regex);
        String [] ret = new String[values.length];
        for (int i = 0 ; i < values.length ; i++) {
            ret[i] = values[i].trim();
        }

        return ret;
    }

    private static boolean containsAll(Collection<String> col, String [] values) {
        if (col == null) {
            return false;
        }

        for (String val: values) {
            if (! col.contains(val)) {
                return false;
            }
        }

        return true;
    }

    class PreflightInvoker implements Invoker {

        private final Request request;

        PreflightInvoker(final Request request) {
            this.request = request;
        }

        @Override
        public ProxyConnection invoke(ExecutionContext executionContext, Request serverRequest, Handler<ProxyResponse> result) {
            final ProxyConnection proxyConnection = new PreflightProxyConnection(request, result);

            serverRequest
                    .bodyHandler(proxyConnection::write)
                    .endHandler(endResult -> proxyConnection.end());

            return proxyConnection;
        }
    }

    class PreflightProxyConnection implements ProxyConnection {

        private final Handler<ProxyResponse> proxyResponseHandler;
        private final Request request;

        PreflightProxyConnection(final Request request, final Handler<ProxyResponse> proxyResponseHandler) {
            this.request = request;
            this.proxyResponseHandler = proxyResponseHandler;
        }

        @Override
        public ProxyConnection write(Buffer chunk) {
            return this;
        }

        @Override
        public void end() {
            // Prepare response
            PreflightProxyResponse preflightProxyResponse = new PreflightProxyResponse();

            // 1. If the Origin header is not present terminate this set of steps. The request is outside the scope of
            //  this specification.
            // 2. If the value of the Origin header is not a case-sensitive match for any of the values in list of
            //  origins, do not set any additional headers and terminate this set of steps.
            String originHeader = request.headers().getFirst(HttpHeaders.ORIGIN);
            if (! isOriginAllowed(originHeader)) {
                preflightProxyResponse.status = configuration.getCorsErrorStatusCode();
            }

            // 3. Let method be the value as result of parsing the Access-Control-Request-Method header.
            // If there is no Access-Control-Request-Method header or if parsing failed, do not set any additional
            //  headers and terminate this set of steps. The request is outside the scope of this specification.
            String accessControlRequestMethod = request.headers().getFirst(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD);
            if (! isRequestMethodsValid(accessControlRequestMethod)) {
                preflightProxyResponse.status = configuration.getCorsErrorStatusCode();
            }

            String accessControlRequestHeaders = request.headers().getFirst(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS);
            if (! isRequestHeadersValid(accessControlRequestHeaders)) {
                preflightProxyResponse.status = configuration.getCorsErrorStatusCode();
            }

            proxyResponseHandler.handle(preflightProxyResponse);
            preflightProxyResponse.endHandler.handle(null);
        }
    }

    class PreflightProxyResponse implements ProxyResponse {

        private final HttpHeaders headers = new HttpHeaders();

        private Handler<Buffer> bodyHandler;
        private Handler<Void> endHandler;

        int status = HttpStatusCode.OK_200;

        @Override
        public int status() {
            return status;
        }

        @Override
        public HttpHeaders headers() {
            return headers;
        }

        @Override
        public ProxyResponse bodyHandler(Handler<Buffer> bodyHandler) {
            this.bodyHandler = bodyHandler;
            return this;
        }

        @Override
        public ProxyResponse endHandler(Handler<Void> endHandler) {
            this.endHandler = endHandler;
            return this;
        }
    }
}
