/*
 * Copyright 2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package example;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Map;
import java.util.Set;


public class OAuth2SmsAuthenticationToken  extends OAuth2AuthorizationGrantAuthenticationToken {


    //private final Set<String> scopes;
    private final String code;

    private final String redirectUri;

    private final Set<String> requestedScopes;

    /**
     * Constructs an {@code OAuth2AuthorizationCodeAuthenticationToken} using the provided parameters.
     *
     * @param code the authorization code
     * @param clientPrincipal the authenticated client principal
     * @param redirectUri the redirect uri
     * @param additionalParameters the additional parameters
     */
    public OAuth2SmsAuthenticationToken(Authentication clientPrincipal,String code,@Nullable String redirectUri, Set<String> requestedScopes, @Nullable Map<String, Object> additionalParameters) {
        super(MyAuthorizationGrantType.SMS_CODE, clientPrincipal, additionalParameters);
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        //this.scopes = Collections.unmodifiableSet(CollectionUtils.isNotEmpty(scopes) ? new HashSet<>(scopes) : Collections.emptySet());
        this.code = code;
        this.requestedScopes = requestedScopes;
        //this.scopes = Collections.unmodifiableSet(CollectionUtils.isNotEmpty(scopes) ? new HashSet<>(scopes) : Collections.emptySet());
        this.redirectUri = redirectUri;
    }


    /**
     * Returns the redirect uri.
     *
     * @return the redirect uri
     */
    @Nullable
    public String getRedirectUri() {
        return this.redirectUri;
    }


}
