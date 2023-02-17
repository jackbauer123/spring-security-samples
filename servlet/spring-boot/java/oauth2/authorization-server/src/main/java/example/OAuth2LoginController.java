/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.stereotype.Controller;

/**
 * OAuth2 Log in controller.
 *
 * @author Joe Grandja
 * @author Rob Winch
 */
@Controller
public class OAuth2LoginController {



	/*@GetMapping("/login")
	public String login(Model model){
		return "login";
	}*/


	/*@RequestMapping("/oauth2/consent")
	public String consent(@RequestParam String scope, @RequestParam String client_id, @RequestParam String state, Authentication authentication, Model model) {
		System.out.println("/oauth2/consent------>scope:{} client_id:{} state:{} authentication:{}");

		model.addAttribute("scopes", scope.split(" "));
		model.addAttribute("clientId", client_id);
		model.addAttribute("state", state);
		return "consent";
	}*/


}
