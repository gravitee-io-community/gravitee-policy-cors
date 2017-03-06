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

import io.gravitee.policy.cors.configuration.CorsPolicyConfiguration;
import io.gravitee.policy.cors.utils.CaseInsensitiveHashSet;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.Collections;

import static org.mockito.MockitoAnnotations.initMocks;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class CorsPolicyTest {

    @Mock
    private CorsPolicyConfiguration corsPolicyConfiguration;

    private CorsPolicy corsPolicy;

    @Before
    public void init() {
        initMocks(this);

        corsPolicy = new CorsPolicy(corsPolicyConfiguration);
    }

    @Test
    public void testAccessControlRequestHeaders01() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowHeaders()).thenReturn(null);
        boolean result = corsPolicy.isRequestHeadersValid(null);
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestHeaders02() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowHeaders()).thenReturn(Collections.emptySet());
        boolean result = corsPolicy.isRequestHeadersValid(null);
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestHeaders03() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowHeaders()).thenReturn(new CaseInsensitiveHashSet(Collections.singleton("Origin")));
        boolean result = corsPolicy.isRequestHeadersValid(null);
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestHeaders04() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowHeaders()).thenReturn(new CaseInsensitiveHashSet(Collections.singleton("Origin")));
        boolean result = corsPolicy.isRequestHeadersValid("Origin");
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestHeaders05() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowHeaders()).thenReturn(new CaseInsensitiveHashSet(Collections.singleton("Origin")));
        boolean result = corsPolicy.isRequestHeadersValid("Origin, X-Gravitee-Api-Key");
        Assert.assertFalse(result);
    }

    @Test
    public void testAccessControlRequestHeaders06() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowHeaders()).thenReturn(new CaseInsensitiveHashSet(Collections.singleton("Origin")));
        boolean result = corsPolicy.isRequestHeadersValid("X-Gravitee-Api-Key");
        Assert.assertFalse(result);
    }

    @Test
    public void testAccessControlRequestHeaders07() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowHeaders()).thenReturn(new CaseInsensitiveHashSet(Collections.singleton("Origin")));
        boolean result = corsPolicy.isRequestHeadersValid("");
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestHeaders08_caseInsensitive() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowHeaders()).thenReturn(new CaseInsensitiveHashSet(Collections.singleton("Origin")));
        boolean result = corsPolicy.isRequestHeadersValid("ORIGIN");
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestHeaders09_caseInsensitive() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowHeaders()).thenReturn(new CaseInsensitiveHashSet(Arrays.asList("Origin", "X-Gravitee-Api-Key")));
        boolean result = corsPolicy.isRequestHeadersValid("ORIGIN");
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestMethods01() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowMethods()).thenReturn(null);
        boolean result = corsPolicy.isRequestMethodsValid(null);
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestMethods02() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowMethods()).thenReturn(new CaseInsensitiveHashSet(Collections.emptySet()));
        boolean result = corsPolicy.isRequestMethodsValid(null);
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestMethods03() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowMethods()).thenReturn(new CaseInsensitiveHashSet(Collections.singleton("GET")));
        boolean result = corsPolicy.isRequestMethodsValid(null);
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestMethods04() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowMethods()).thenReturn(new CaseInsensitiveHashSet(Collections.singleton("GET")));
        boolean result = corsPolicy.isRequestMethodsValid("GET");
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestMethods05() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowMethods()).thenReturn(new CaseInsensitiveHashSet(Collections.singleton("GET")));
        boolean result = corsPolicy.isRequestMethodsValid("GET, POST");
        Assert.assertFalse(result);
    }

    @Test
    public void testAccessControlRequestMethods06() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowMethods()).thenReturn(new CaseInsensitiveHashSet(Arrays.asList("GET", "POST")));
        boolean result = corsPolicy.isRequestMethodsValid("GET, POST");
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestMethods07() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowMethods()).thenReturn(new CaseInsensitiveHashSet(Arrays.asList("GET", "POST")));
        boolean result = corsPolicy.isRequestMethodsValid("GET");
        Assert.assertTrue(result);
    }

    @Test
    public void testAccessControlRequestMethods08() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowMethods()).thenReturn(new CaseInsensitiveHashSet(Collections.singleton("POST")));
        boolean result = corsPolicy.isRequestMethodsValid("GET");
        Assert.assertFalse(result);
    }

    @Test
    public void testAccessControlRequestMethods09() {
        Mockito.when(corsPolicyConfiguration.getAccessControlAllowMethods()).thenReturn(new CaseInsensitiveHashSet(Collections.singleton("GET")));
        boolean result = corsPolicy.isRequestMethodsValid("");
        Assert.assertTrue(result);
    }
}
