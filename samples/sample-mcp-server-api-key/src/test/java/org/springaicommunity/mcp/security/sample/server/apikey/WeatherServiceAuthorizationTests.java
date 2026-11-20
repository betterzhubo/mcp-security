/*
 * Copyright 2026-2026 the original author or authors.
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

package org.springaicommunity.mcp.security.sample.server.apikey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = WeatherServiceAuthorizationTests.TestConfiguration.class)
class WeatherServiceAuthorizationTests {

	private static final String WEATHER_RESPONSE = """
			{
			  "current": {
			    "time": "2026-11-20T12:00:00",
			    "interval": 900,
			    "temperature_2m": 12.4
			  }
			}
			""";

	private final WeatherService weatherService;

	private final MockRestServiceServer mockServer;

	@Autowired
	WeatherServiceAuthorizationTests(WeatherService weatherService, MockRestServiceServer mockServer) {
		this.weatherService = weatherService;
		this.mockServer = mockServer;
	}

	@BeforeEach
	void resetMockServer() {
		this.mockServer.reset();
	}

	@Test
	@WithMockUser(authorities = "SCOPE_weather.read")
	void allowsCallWithWeatherReadAuthority() {
		this.mockServer.expect(ExpectedCount.once(), requestTo(startsWith("https://api.open-meteo.com/v1/forecast")))
			.andRespond(withSuccess(WEATHER_RESPONSE, MediaType.APPLICATION_JSON));

		var result = this.weatherService.getTemperature(51.5, -0.12);

		assertThat(result.current().temperature_2m()).isEqualTo(12.4);
		this.mockServer.verify();
	}

	@Test
	@WithMockUser(authorities = "SCOPE_weather.write")
	void rejectsWriteOnlyKeyWithoutWeatherReadAuthority() {
		assertThatThrownBy(() -> this.weatherService.getTemperature(51.5, -0.12))
			.isInstanceOf(AccessDeniedException.class);
	}

	@Configuration(proxyBeanMethods = false)
	@EnableMethodSecurity
	static class TestConfiguration {

		@Bean
		RestClient.Builder restClientBuilder() {
			return RestClient.builder();
		}

		@Bean
		MockRestServiceServer mockRestServiceServer(RestClient.Builder restClientBuilder) {
			return MockRestServiceServer.bindTo(restClientBuilder).build();
		}

		@Bean
		WeatherService weatherService(RestClient.Builder restClientBuilder) {
			return new WeatherService(restClientBuilder);
		}

	}

}
