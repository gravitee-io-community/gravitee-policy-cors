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
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.policy.PolicyChain;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

/**
 * @author abourdon
 */
public class CorsPolicyTest {

    private static final String DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE = "*";
    private static final String OVERRIDDEN_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE = "http://overridden.com";

    private static final String DEFAULT_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE = "true";
    private static final String OVERRIDDEN_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE = "false";

    private static final String DEFAULT_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE = "X-Foo-Header, X-Bar-Header";
    private static final String OVERRIDDEN_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE = "X-Dummy-Header";

    private static final String DEFAULT_ACCESS_CONTROL_MAX_AGE_VALUE = "10";
    private static final String OVERRIDDEN_ACCESS_CONTROL_MAX_AGE_VALUE = "15";

    private static final String DEFAULT_ACCESS_CONTROL_ALLOW_METHODS_VALUE = "GET, POST";
    private static final String OVERRIDDEN_ACCESS_CONTROL_ALLOW_METHODS_VALUE = "GET, POST, PUT";

    private static final String DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS_VALUE = "X-Foo-Header, X-Bar-Header";
    private static final String OVERRIDDEN_ACCESS_CONTROL_ALLOW_HEADERS_VALUE = "X-Dummy-Header";

    @Mock
    private Request request;

    @Mock
    private Response response;

    @Mock
    private PolicyChain policyChain;

    private CorsPolicy cors;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testAccessControlAllowOriginWhenMissingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration());
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN.toString(), DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowOriginWhenExistingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowOrigin() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN.toString(), DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowOriginWhenExistingFromConfigurationAndOverridingResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowOrigin() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE;
            }

            @Override
            public boolean isOverrideAccessControlAllowOrigin() {
                return true;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN.toString(), DEFAULT_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowOriginWhenExistingFromConfigurationAndNotExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowOrigin() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<>();

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_ALLOW_ORIGIN_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowCredentialsWhenMissingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration());
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS.toString(), DEFAULT_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowCredentialsWhenExistingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowCredentials() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS.toString(), DEFAULT_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowCredentialsWhenExistingFromConfigurationAndOverridingResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowCredentials() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE;
            }

            @Override
            public boolean isOverrideAccessControlAllowCredentials() {
                return true;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS.toString(), DEFAULT_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowCredentialsWhenExistingFromConfigurationAndNotExistingResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowCredentials() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<>();

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_ALLOW_CREDENTIAL_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlExposeHeadersWhenMissingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration());
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_EXPOSE_HEADERS.toString(), DEFAULT_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_EXPOSE_HEADERS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlExposeHeadersWhenExistingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlExposeHeaders() {
                return OVERRIDDEN_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_EXPOSE_HEADERS.toString(), DEFAULT_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_EXPOSE_HEADERS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlExposeHeadersWhenExistingFromConfigurationAndOverridingResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlExposeHeaders() {
                return OVERRIDDEN_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE;
            }

            @Override
            public boolean isOverrideAccessControlExposeHeaders() {
                return true;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_EXPOSE_HEADERS.toString(), DEFAULT_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_EXPOSE_HEADERS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlExposeHeadersWhenExistingFromConfigurationAndNotExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlExposeHeaders() {
                return OVERRIDDEN_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<>();

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_EXPOSE_HEADERS.toString()));
        verify(policyChain).doNext(request, response);
    }


    @Test
    public void testAccessControlMaxAgeWhenMissingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration());
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_MAX_AGE.toString(), DEFAULT_ACCESS_CONTROL_MAX_AGE_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_MAX_AGE_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_MAX_AGE.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlMaxAgeWhenExistingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlMaxAge() {
                return OVERRIDDEN_ACCESS_CONTROL_MAX_AGE_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_MAX_AGE.toString(), DEFAULT_ACCESS_CONTROL_MAX_AGE_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_MAX_AGE_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_MAX_AGE.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlMaxAgeWhenExistingFromConfigurationAndOverridingResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlMaxAge() {
                return OVERRIDDEN_ACCESS_CONTROL_MAX_AGE_VALUE;
            }

            @Override
            public boolean isOverrideAccessControlMaxAge() {
                return true;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_MAX_AGE.toString(), DEFAULT_ACCESS_CONTROL_MAX_AGE_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_MAX_AGE_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_MAX_AGE.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlMaxAgeWhenExistingFromConfigurationAndNotExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlMaxAge() {
                return OVERRIDDEN_ACCESS_CONTROL_MAX_AGE_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<>();

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_MAX_AGE_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_MAX_AGE.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowMethodsWhenMissingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration());
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_METHODS.toString(), DEFAULT_ACCESS_CONTROL_ALLOW_METHODS_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_ALLOW_METHODS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_METHODS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowMethodsWhenExistingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowMethods() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_METHODS_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_METHODS.toString(), DEFAULT_ACCESS_CONTROL_ALLOW_METHODS_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_ALLOW_METHODS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_METHODS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowMethodsWhenExistingFromConfigurationAndOverridingResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowMethods() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_METHODS_VALUE;
            }

            @Override
            public boolean isOverrideAccessControlAllowMethods() {
                return true;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_METHODS.toString(), DEFAULT_ACCESS_CONTROL_ALLOW_METHODS_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_ALLOW_METHODS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_METHODS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowMethodsWhenExistingFromConfigurationAndNotExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowMethods() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_METHODS_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<>();

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_ALLOW_METHODS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_METHODS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowHeadersWhenMissingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration());
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_HEADERS.toString(), DEFAULT_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_HEADERS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowHeadersWhenExistingFromConfigurationAndExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowHeaders() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_HEADERS_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_HEADERS.toString(), DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_HEADERS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowHeadersWhenExistingFromConfigurationAndOverridingResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowHeaders() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_HEADERS_VALUE;
            }

            @Override
            public boolean isOverrideAccessControlAllowHeaders() {
                return true;
            }
        });
        Map<String, String> headers = new HashMap<String, String>() {
            {
                put(HttpHeader.ACCESS_CONTROL_ALLOW_HEADERS.toString(), DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS_VALUE);
            }
        };

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_ALLOW_HEADERS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_HEADERS.toString()));
        verify(policyChain).doNext(request, response);
    }

    @Test
    public void testAccessControlAllowHeadersWhenExistingFromConfigurationAndNotExistingInResponse() throws Exception {
        cors = new CorsPolicy(new CorsPolicyConfiguration() {
            @Override
            public String getAccessControlAllowHeaders() {
                return OVERRIDDEN_ACCESS_CONTROL_ALLOW_HEADERS_VALUE;
            }
        });
        Map<String, String> headers = new HashMap<>();

        doNothing().when(policyChain).doNext(request, response);
        stub(response.headers()).toReturn(headers);

        cors.onResponse(request, response, policyChain);
        assertEquals(1, headers.size());
        assertEquals(OVERRIDDEN_ACCESS_CONTROL_ALLOW_HEADERS_VALUE, headers.get(HttpHeader.ACCESS_CONTROL_ALLOW_HEADERS.toString()));
        verify(policyChain).doNext(request, response);
    }

}