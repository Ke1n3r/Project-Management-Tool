package com.biswas.project_management_backend;

import com.biswas.project_management_backend.dto.*;
import com.biswas.project_management_backend.repository.RefreshTokenRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RefreshTokenIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private static String accessToken;
    private static String refreshToken;
    private static Long userId;

    @Test
    @Order(1)
    void shouldRegisterCompanyAdminWithTokens() throws Exception {
        RegisterCompanyRequestDto request = new RegisterCompanyRequestDto();
        request.setCompanyName("Test Company");
        request.setDomain("testcompany.com");

        RegisterCompanyRequestDto.AdminDto admin = new RegisterCompanyRequestDto.AdminDto();
        admin.setName("testadmin");
        admin.setEmail("testadmin@test.com");
        admin.setPassword("password123");
        request.setAdmin(admin);

        MvcResult result = mockMvc.perform(post("/api/auth/register/company")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.user.username").value("testadmin"))
                .andReturn();

        AuthResponseDto response = objectMapper.readValue(
                result.getResponse().getContentAsString(), AuthResponseDto.class);

        accessToken = response.getToken();
        refreshToken = response.getRefreshToken();
        userId = response.getUser().getId();

        // Verify token stored in DB
        assertThat(refreshTokenRepository.findByToken(refreshToken)).isPresent();
    }

    @Test
    @Order(2)
    void shouldRotateTokensOnLogin() throws Exception {
        LoginRequestDto loginRequest = new LoginRequestDto();
        loginRequest.setEmail("testadmin@test.com");
        loginRequest.setPassword("password123");

        String oldRefreshToken = refreshToken;

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        AuthResponseDto response = objectMapper.readValue(
                result.getResponse().getContentAsString(), AuthResponseDto.class);

        String newRefreshToken = response.getRefreshToken();

        // Verify token rotation - old deleted, new created
        assertThat(refreshTokenRepository.findByToken(oldRefreshToken)).isEmpty();
        assertThat(refreshTokenRepository.findByToken(newRefreshToken)).isPresent();

        accessToken = response.getToken();
        refreshToken = newRefreshToken;
    }

    @Test
    @Order(3)
    void shouldRefreshTokensSuccessfully() throws Exception {
        RefreshTokenRequestDto request = new RefreshTokenRequestDto();
        request.setRefreshToken(refreshToken);

        String oldRefreshToken = refreshToken;

        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        AuthResponseDto response = objectMapper.readValue(
                result.getResponse().getContentAsString(), AuthResponseDto.class);

        // Verify new tokens generated and old token deleted
        assertThat(response.getToken()).isNotEqualTo(accessToken);
        assertThat(response.getRefreshToken()).isNotEqualTo(oldRefreshToken);
        assertThat(refreshTokenRepository.findByToken(oldRefreshToken)).isEmpty();

        accessToken = response.getToken();
        refreshToken = response.getRefreshToken();
    }

    @Test
    @Order(4)
    void shouldRejectInvalidRefreshToken() throws Exception {
        RefreshTokenRequestDto request = new RefreshTokenRequestDto();
        request.setRefreshToken("invalid-token-12345");

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(5)
    void shouldInvalidateTokenOnLogout() throws Exception {
        RefreshTokenRequestDto request = new RefreshTokenRequestDto();
        request.setRefreshToken(refreshToken);

        // Verify token exists before logout
        assertThat(refreshTokenRepository.findByToken(refreshToken)).isPresent();

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().string("Logged out successfully"));

        // Verify token deleted
        assertThat(refreshTokenRepository.findByToken(refreshToken)).isEmpty();
    }

    @Test
    @Order(6)
    void shouldRejectTokenAfterLogout() throws Exception {
        RefreshTokenRequestDto request = new RefreshTokenRequestDto();
        request.setRefreshToken(refreshToken);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(7)
    void shouldMaintainOneTokenPerUser() throws Exception {
        LoginRequestDto loginRequest = new LoginRequestDto();
        loginRequest.setEmail("testadmin@test.com");
        loginRequest.setPassword("password123");

        // Login twice
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());

        // Verify only one token exists
        long tokenCount = refreshTokenRepository.findAll().stream()
                .filter(token -> token.getUser().getId().equals(userId))
                .count();

        assertThat(tokenCount).isEqualTo(1);
    }
}