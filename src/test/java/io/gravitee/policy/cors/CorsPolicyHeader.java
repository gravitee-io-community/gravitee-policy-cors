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

import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * @author Aurélien Bourdon (aurelien.bourdon at gmail.com)
 */
public abstract class CorsPolicyHeader {

    private static CorsPolicyConfigurationProperty<String> newDefaultCorsPolicyConfigurationProperty() {
        return new CorsPolicyConfigurationProperty<String>() {
            {
                setEnabled(false);
            }
        };
    }

    @Mock
    protected Request request;

    @Mock
    protected Response response;

    @Mock
    protected PolicyChain policyChain;

    protected CorsPolicy cors;

    protected CorsPolicyConfiguration configuration;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        configuration = new CorsPolicyConfiguration();
        configuration.setAccessControlAllowOrigin(newDefaultCorsPolicyConfigurationProperty());
        configuration.setAccessControlAllowCredentials(newDefaultCorsPolicyConfigurationProperty());
        configuration.setAccessControlExposeHeaders(newDefaultCorsPolicyConfigurationProperty());
        configuration.setAccessControlMaxAge(newDefaultCorsPolicyConfigurationProperty());
        configuration.setAccessControlAllowMethods(newDefaultCorsPolicyConfigurationProperty());
        configuration.setAccessControlAllowHeaders(newDefaultCorsPolicyConfigurationProperty());
        cors = new CorsPolicy(configuration);
    }

    @Test
    public abstract void testHeaderWhenConfigurationDeactivatedAndExistingInResponse() throws Exception;

    @Test
    public abstract void testHeaderWhenConfigurationActivatedAndNotOverridingAndExistingInResponse() throws Exception;

    @Test
    public abstract void testHeaderWhenConfigurationActivatedAndNotOverridingWithNullValueAndNotExistingInResponse() throws Exception;

    @Test
    public abstract void testHeaderWhenConfigurationActivatedAndNotOverridingWithNonNullValueAndNotExistingInResponse() throws Exception;

    @Test
    public abstract void testHeaderWhenConfigurationActivatedAndOverridingWithNullValueAndNotExistingInResponse() throws Exception;

    @Test
    public abstract void testHeaderWhenConfigurationActivatedAndOverridingWithNonNullValueAndNotExistingInResponse() throws Exception;

    @Test
    public abstract void testHeaderWhenConfigurationActivatedAndOverridingWithNullValueAndExistingInResponse() throws Exception;

    @Test
    public abstract void testHeaderWhenConfigurationActivatedAndOverridingWithNonNullValueAndExistingInResponse() throws Exception;

    @Test
    public abstract void testHeaderWhenConfigurationActivatedAndWithoutPreflightRequest() throws Exception;

}
