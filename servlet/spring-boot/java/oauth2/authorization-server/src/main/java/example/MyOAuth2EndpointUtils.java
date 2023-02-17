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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public final class MyOAuth2EndpointUtils {
    static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private static boolean checkRequired(MultiValueMap<String, String> parameters, String parameterName, String parameterValue) {
        return !StringUtils.hasText(parameterValue) || parameters.get(parameterName).size() != 1;
    }

    private static boolean checkOptional(MultiValueMap<String, String> parameters, String parameterName, String parameterValue) {
        return StringUtils.hasText(parameterValue) && parameters.get(parameterName).size() != 1;
    }

    public static String checkParameter(MultiValueMap<String, String> parameters, String parameterName, boolean isRequired, String errorCode, String errorUri) {
        String value = parameters.getFirst(parameterName);
        if (isRequired) {
            if (checkRequired(parameters, parameterName, value)) {
                MyOAuth2EndpointUtils.throwError(errorCode, parameterName, errorUri);
            }
        } else {
            if (checkOptional(parameters, parameterName, value)) {
                MyOAuth2EndpointUtils.throwError(errorCode, parameterName, errorUri);
            }
        }

        return value;
    }

    public static String checkRequiredParameter(MultiValueMap<String, String> parameters, String parameterName, String errorCode, String errorUri) {
        return checkParameter(parameters, parameterName, true, errorCode, errorUri);
    }

    public static String checkRequiredParameter(MultiValueMap<String, String> parameters, String parameterName, String errorCode) {
        return checkRequiredParameter(parameters, parameterName, errorCode, MyOAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
    }

    public static String checkRequiredParameter(MultiValueMap<String, String> parameters, String parameterName) {
        return checkRequiredParameter(parameters, parameterName, OAuth2ErrorCodes.INVALID_REQUEST);
    }

    public static String checkOptionalParameter(MultiValueMap<String, String> parameters, String parameterName, String errorCode, String errorUri) {
        return checkParameter(parameters, parameterName, false, errorCode, errorUri);
    }

    public static String checkOptionalParameter(MultiValueMap<String, String> parameters, String parameterName) {
        return checkOptionalParameter(parameters, parameterName, OAuth2ErrorCodes.INVALID_REQUEST);
    }
    public static String checkOptionalParameter(MultiValueMap<String, String> parameters, String parameterName, String errorCode) {
        return checkOptionalParameter(parameters, parameterName, errorCode, MyOAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
    }


    private MyOAuth2EndpointUtils() {
    }

    static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            if (values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }

    static Map<String, Object> getParametersIfMatchesAuthorizationCodeGrantRequest(HttpServletRequest request, String... exclusions) {
        if (!matchesAuthorizationCodeGrantRequest(request)) {
            return Collections.emptyMap();
        }
        Map<String, Object> parameters = new HashMap<>(getParameters(request).toSingleValueMap());
        for (String exclusion : exclusions) {
            parameters.remove(exclusion);
        }
        return parameters;
    }

    static boolean matchesAuthorizationCodeGrantRequest(HttpServletRequest request) {
        return AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(
                request.getParameter(OAuth2ParameterNames.GRANT_TYPE)) &&
                request.getParameter(OAuth2ParameterNames.CODE) != null;
    }

    static boolean matchesPkceTokenRequest(HttpServletRequest request) {
        return matchesAuthorizationCodeGrantRequest(request) &&
                request.getParameter(PkceParameterNames.CODE_VERIFIER) != null;
    }

    static void throwError(String errorCode, String parameterName, String errorUri) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        throw new OAuth2AuthenticationException(error);
    }
}
