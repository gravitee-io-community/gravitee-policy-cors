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

import java.util.HashMap;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

/**
 * @author Aurélien Bourdon (aurelien.bourdon at gmail.com)
 */
public class CorsPolicyHeaderAccessControlAllowHeaders extends CorsPolicyHeader {

    private static final String DEFAULT_HEADER_VALUE = "*";

    @Override
    public void testHeaderWhenConfigurationDeactivatedAndExistingInResponse() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, DEFAULT_HEADER_VALUE);
            }
        });

        doNothing().when(policyChain).doNext(request, response);
        stub(request.method()).toReturn(HttpMethod.OPTIONS);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);

        assertEquals(1, headers.size());
        assertEquals(DEFAULT_HEADER_VALUE, headers.getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS));
        verify(policyChain).doNext(request, response);
    }

    @Override
    public void testHeaderWhenConfigurationActivatedAndNotOverridingAndExistingInResponse() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, DEFAULT_HEADER_VALUE);
            }
        });
        doNothing().when(policyChain).doNext(request, response);
        stub(request.method()).toReturn(HttpMethod.OPTIONS);
        stub(response.headers()).toReturn(headers);

        configuration.getAccessControlAllowHeaders().setEnabled(true);
        cors.onResponse(request, response, policyChain);

        assertEquals(1, headers.size());
        String expectedHeaderValue = String.format("%s, %s", DEFAULT_HEADER_VALUE, GraviteeHttpHeader.X_GRAVITEE_API_KEY);
        assertEquals(expectedHeaderValue, headers.getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS));
        verify(policyChain).doNext(request, response);
    }

    @Override
    public void testHeaderWhenConfigurationActivatedAndNotOverridingWithNullValueAndNotExistingInResponse() throws Exception {
        final HttpHeaders headers = new HttpHeaders();

        doNothing().when(policyChain).doNext(request, response);
        stub(request.method()).toReturn(HttpMethod.OPTIONS);
        stub(response.headers()).toReturn(headers);

        configuration.getAccessControlAllowHeaders().setEnabled(true);
        configuration.getAccessControlAllowHeaders().setValue(null);
        cors.onResponse(request, response, policyChain);

        assertEquals(1, headers.size());
        assertEquals(GraviteeHttpHeader.X_GRAVITEE_API_KEY, headers.getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS));
        verify(policyChain).doNext(request, response);
    }

    @Override
    public void testHeaderWhenConfigurationActivatedAndNotOverridingWithNonNullValueAndNotExistingInResponse() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        doNothing().when(policyChain).doNext(request, response);
        stub(request.method()).toReturn(HttpMethod.OPTIONS);
        stub(response.headers()).toReturn(headers);

        configuration.getAccessControlAllowHeaders().setEnabled(true);
        configuration.getAccessControlAllowHeaders().setValue("X-Foo-Header, X-Bar-Header");
        cors.onResponse(request, response, policyChain);

        assertEquals(1, headers.size());
        String expectedHeaderValue = String.format("X-Foo-Header, X-Bar-Header, %s", GraviteeHttpHeader.X_GRAVITEE_API_KEY);
        assertEquals(expectedHeaderValue, headers.getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS));
        verify(policyChain).doNext(request, response);
    }

    @Override
    public void testHeaderWhenConfigurationActivatedAndOverridingWithNullValueAndNotExistingInResponse() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        doNothing().when(policyChain).doNext(request, response);
        stub(request.method()).toReturn(HttpMethod.OPTIONS);
        stub(response.headers()).toReturn(headers);

        configuration.getAccessControlAllowHeaders().setEnabled(true);
        configuration.getAccessControlAllowHeaders().setOverridden(true);
        configuration.getAccessControlAllowHeaders().setValue(null);
        cors.onResponse(request, response, policyChain);

        assertEquals(1, headers.size());
        assertEquals(GraviteeHttpHeader.X_GRAVITEE_API_KEY, headers.getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS));
        verify(policyChain).doNext(request, response);
    }

    @Override
    public void testHeaderWhenConfigurationActivatedAndOverridingWithNonNullValueAndNotExistingInResponse() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        doNothing().when(policyChain).doNext(request, response);
        stub(request.method()).toReturn(HttpMethod.OPTIONS);
        stub(response.headers()).toReturn(headers);

        configuration.getAccessControlAllowHeaders().setEnabled(true);
        configuration.getAccessControlAllowHeaders().setOverridden(true);
        configuration.getAccessControlAllowHeaders().setValue("X-Foo-Header, X-Bar-Header");
        cors.onResponse(request, response, policyChain);

        assertEquals(1, headers.size());
        String expectedHeaderValue = String.format("X-Foo-Header, X-Bar-Header, %s", GraviteeHttpHeader.X_GRAVITEE_API_KEY);
        assertEquals(expectedHeaderValue, headers.getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS));
        verify(policyChain).doNext(request, response);
    }

    @Override
    public void testHeaderWhenConfigurationActivatedAndOverridingWithNullValueAndExistingInResponse() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, DEFAULT_HEADER_VALUE);
            }
        });
        doNothing().when(policyChain).doNext(request, response);
        stub(request.method()).toReturn(HttpMethod.OPTIONS);
        stub(response.headers()).toReturn(headers);

        configuration.getAccessControlAllowHeaders().setEnabled(true);
        configuration.getAccessControlAllowHeaders().setOverridden(true);
        configuration.getAccessControlAllowHeaders().setValue(null);
        cors.onResponse(request, response, policyChain);

        assertEquals(1, headers.size());
        assertEquals(GraviteeHttpHeader.X_GRAVITEE_API_KEY, headers.getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS));
        verify(policyChain).doNext(request, response);
    }

    @Override
    public void testHeaderWhenConfigurationActivatedAndOverridingWithNonNullValueAndExistingInResponse() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, DEFAULT_HEADER_VALUE);
            }
        });
        doNothing().when(policyChain).doNext(request, response);
        stub(request.method()).toReturn(HttpMethod.OPTIONS);
        stub(response.headers()).toReturn(headers);

        configuration.getAccessControlAllowHeaders().setEnabled(true);
        configuration.getAccessControlAllowHeaders().setOverridden(true);
        configuration.getAccessControlAllowHeaders().setValue("X-Foo-Header, X-Bar-Header");
        cors.onResponse(request, response, policyChain);

        assertEquals(1, headers.size());
        String expectedHeaderValue = String.format("X-Foo-Header, X-Bar-Header, %s", GraviteeHttpHeader.X_GRAVITEE_API_KEY);
        assertEquals(expectedHeaderValue, headers.getFirst(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS));
        verify(policyChain).doNext(request, response);
    }

    @Override
    public void testHeaderWhenConfigurationActivatedAndWithoutPreflightRequest() throws Exception {
        doNothing().when(policyChain).doNext(request, response);
        stub(request.method()).toReturn(HttpMethod.GET);

        cors.onResponse(request, response, policyChain);

        verify(policyChain).doNext(request, response);
    }

}