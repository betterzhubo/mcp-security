/*
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

package org.springaicommunity.mcp.security.sample.server.securedtools;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
@ContextConfiguration(classes = HistoricalWeatherServiceAuthorizationTests.TestConfiguration.class)
class HistoricalWeatherServiceAuthorizationTests {

	private static final String WEATHER_RESPONSE = """
			{
			  "daily": {
			    "time": ["2026-11-20"],
			    "temperature_2m_max": [14.2],
			    "temperature_2m_min": [7.1]
			  }
			}
			""";

	private final HistoricalWeatherService weatherService;

	private final MockRestServiceServer mockServer;

	HistoricalWeatherServiceAuthorizationTests(HistoricalWeatherService weatherService,
			MockRestServiceServer mockServer) {
		this.weatherService = weatherService;
		this.mockServer = mockServer;
	}

	@BeforeEach
	void resetMockServer() {
		this.mockServer.reset();
	}

	@Test
	@WithMockUser(authorities = "SCOPE_weather.read")
	void allowsCallWithWeatherReadScope() {
		this.mockServer.expect(ExpectedCount.times(5),
				requestTo(startsWith("https://archive-api.open-meteo.com/v1/archive")))
			.andRespond(withSuccess(WEATHER_RESPONSE, MediaType.APPLICATION_JSON));

		var result = this.weatherService.getHistoricalWeatherData(51.5, -0.12);

		assertThat(result.dailyTemperatures()).hasSize(5);
		this.mockServer.verify();
	}

	@Test
	@WithMockUser(authorities = "SCOPE_weather.write")
	void rejectsAuthenticatedUserWithoutWeatherReadScope() {
		assertThatThrownBy(() -> this.weatherService.getHistoricalWeatherData(51.5, -0.12))
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
		HistoricalWeatherService historicalWeatherService(RestClient.Builder restClientBuilder,
				MockRestServiceServer mockRestServiceServer) {
			return new HistoricalWeatherService(restClientBuilder);
		}

	}

}
