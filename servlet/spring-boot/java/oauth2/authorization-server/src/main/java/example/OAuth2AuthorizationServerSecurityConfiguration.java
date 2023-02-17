/*
 * Copyright 2021 the original author or authors.
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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * OAuth Authorization Server Configuration.
 *
 * @author Steve Riesenberg
 */
@Configuration
@EnableWebSecurity
public class OAuth2AuthorizationServerSecurityConfiguration {




	/*@Bean
	public OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
				.issuer("https://example.com")
				.authorizationEndpoint("/oauth2/v1/authorize")
				.tokenEndpoint("/oauth2/v1/token")
				.tokenIntrospectionEndpoint("/oauth2/v1/introspect")
				.tokenRevocationEndpoint("/oauth2/v1/revoke")
				.jwkSetEndpoint("/oauth2/v1/jwks")
				.oidcUserInfoEndpoint("/connect/v1/userinfo")
				.oidcClientRegistrationEndpoint("/connect/v1/register")
				.build();
	}*/


	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();
		http.apply(authorizationServerConfigurer);
		//OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity),

		authorizationServerConfigurer
				.clientAuthentication(clientAuthentication ->
						clientAuthentication
								.authenticationConverter(new OAuth2AuthorizationSmsAuthenticationConverter())
								.authenticationProvider(new OAuth2SmsAuthenticationProvider(MyOAuth2ConfigurerUtils.getRegisteredClientRepository(http),
										new InMemoryOAuth2AuthorizationService(),
										MyOAuth2ConfigurerUtils.getTokenGenerator(http)))
								.authenticationSuccessHandler(new SmsAuthenticationSuccessHandler())
								.errorResponseHandler(new SmsAuthenticationFailureHandler())
				)
				.tokenEndpoint(tokenEndpoint ->
						tokenEndpoint.accessTokenRequestConverters(e -> e.add(new OAuth2AuthorizationSmsAuthenticationConverter())));
		http.csrf().disable();
		return http.build();
	}

	/*@Bean
	@Order(2)
	public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
				.authorizeHttpRequests((authorize) -> authorize
						.anyRequest().authenticated()
				)
				.formLogin(Customizer.withDefaults());
		// @formatter:on

		return http.build();
	}*/



	/*@Bean
	@Order(2)
	public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {

		// @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
							.requestMatchers("/vendors/**",
									"/css/**","/js/**","/Roboto/**","/images/**","/fonts/**").permitAll()
					//.requestMatchers(authorizationServerEndpointsMatcher).permitAll()
				.anyRequest().authenticated())
				//.formLogin(Customizer.withDefaults());
			//.formLogin(e -> e.loginPage("/login"))
				//.csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerEndpointsMatcher))
				//.apply(authorizationServerConfigurer)
		;

		// @formatter:on
		return http.build();
	}*/

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		// @formatter:off
		RegisteredClient loginClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("login-client2")
				.clientSecret("{noop}openid-connect")
				//.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(MyAuthorizationGrantType.SMS_CODE)
				.redirectUri("http://127.0.0.1:8081/login/oauth2/code/login-client2")
				.redirectUri("http://127.0.0.1:8081/authorized")
				.redirectUri("https://www.baidu.com")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("message:read")
				.scope("message:write")
				.build();
		// @formatter:on

		return new InMemoryRegisteredClientRepository(loginClient, registeredClient);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		// @formatter:off
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		// @formatter:on
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(KeyPair keyPair) {
		return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
	}

	@Bean
	public AuthorizationServerSettings providerSettings() {
		return AuthorizationServerSettings.builder().issuer("http://127.0.0.1:9000").build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		// @formatter:off
		UserDetails userDetails = User.withDefaultPasswordEncoder()
				.username("user")
				.password("123")
				.roles("USER")
				.build();
		// @formatter:on

		return new InMemoryUserDetailsManager(userDetails);
	}

	@Bean
	//@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

}
