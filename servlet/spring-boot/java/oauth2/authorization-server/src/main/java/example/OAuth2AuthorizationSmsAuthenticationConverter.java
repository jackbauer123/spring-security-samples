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

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

@Component
public class OAuth2AuthorizationSmsAuthenticationConverter implements AuthenticationConverter {



    private static final RequestMatcher OIDC_REQUEST_MATCHER = createOidcRequestMatcher();


    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        // grant_type (REQUIRED)
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!MyAuthorizationGrantType.SMS_CODE.getValue().equals(grantType)) {
            return null;
        }

        MultiValueMap<String, String> parameters = MyOAuth2EndpointUtils.getParameters(request);

        String mobile = parameters.getFirst("mobile");
        String code = parameters.getFirst("code");


        // scope (OPTIONAL)
        String scope = MyOAuth2EndpointUtils.checkOptionalParameter(parameters, OAuth2ParameterNames.SCOPE);
        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(
                    Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        // redirect_uri (REQUIRED)
        // Required only if the "redirect_uri" parameter was included in the authorization request
        String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
        if (StringUtils.hasText(redirectUri) &&
                parameters.get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
            MyOAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.REDIRECT_URI,
                    MyOAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.CLIENT_ID) &&
                    !key.equals(OAuth2ParameterNames.CODE) &&
                    !key.equals(OAuth2ParameterNames.REDIRECT_URI)) {
                additionalParameters.put(key, value.get(0));
            }
        });
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken("login-client2",ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                "openid-connect",additionalParameters);
        clientPrincipal.setAuthenticated(true);

        return new OAuth2SmsAuthenticationToken(clientPrincipal,"sms_code",  redirectUri, requestedScopes,additionalParameters);
    }


    private static RequestMatcher createOidcRequestMatcher() {
        RequestMatcher postMethodMatcher = request -> "POST".equals(request.getMethod());
        RequestMatcher responseTypeParameterMatcher = request ->
                request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;
        RequestMatcher openidScopeMatcher = request -> {
            String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
            return StringUtils.hasText(scope) && scope.contains(OidcScopes.OPENID);
        };
        return new AndRequestMatcher(
                postMethodMatcher, responseTypeParameterMatcher, openidScopeMatcher);
    }
}
