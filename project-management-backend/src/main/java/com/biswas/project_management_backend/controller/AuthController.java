package com.biswas.project_management_backend.controller;

import com.biswas.project_management_backend.dto.AuthResponseDto;
import com.biswas.project_management_backend.dto.LoginRequestDto;
import com.biswas.project_management_backend.dto.RegisterCompanyRequestDto;
import com.biswas.project_management_backend.dto.RegisterRequestDto;
import com.biswas.project_management_backend.dto.RefreshTokenRequestDto;
import com.biswas.project_management_backend.dto.UserDto;
import com.biswas.project_management_backend.dto.mapper.UserDtoMapper;
import com.biswas.project_management_backend.model.RefreshToken;
import com.biswas.project_management_backend.model.User;
import com.biswas.project_management_backend.security.JwtUtil;
import com.biswas.project_management_backend.service.AuthService;
import com.biswas.project_management_backend.service.RefreshTokenService;
import com.biswas.project_management_backend.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final UserDtoMapper userDtoMapper;
    private final AuthService authService;

    @PostMapping("/register/company")
    public ResponseEntity<AuthResponseDto> register(@RequestBody RegisterCompanyRequestDto request) {
        AuthResponseDto response = userService.registerCompanyWithAdmin(request);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDto> register(@RequestBody RegisterRequestDto request) {
        AuthResponseDto response = userService.registerUserWithJoinCode(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public AuthResponseDto login(@RequestBody LoginRequestDto request) {
        return userService.login(request);
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestBody Map<String, String> payload,
            @AuthenticationPrincipal UserDetails userDetails) {

        String oldPassword = payload.get("oldPassword");
        String newPassword = payload.get("newPassword");

        boolean success = authService.changePassword(userDetails.getUsername(), oldPassword, newPassword);
        if (success) {
            return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", "Invalid old password"));
        }
    }


    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequestDto request) {
        try {
            String requestRefreshToken = request.getRefreshToken();

            RefreshToken refreshToken = refreshTokenService.findByToken(requestRefreshToken)
                    .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

            refreshToken = refreshTokenService.verifyExpiration(refreshToken);

            User user = refreshToken.getUser();

            Map<String, Object> claims = new HashMap<>();
            if (user.getCompany() != null) {
                claims.put("companyId", user.getCompany().getId());
            }
            String newAccessToken = jwtUtil.generateToken(user.getEmail(), claims);

            RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user.getId());

            UserDto userDto = userDtoMapper.toDto(user);
            return ResponseEntity.ok(new AuthResponseDto(newAccessToken, newRefreshToken.getToken(), userDto));
        } catch (RuntimeException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody RefreshTokenRequestDto request) {
        String refreshToken = request.getRefreshToken();

        refreshTokenService.findByToken(refreshToken)
                .ifPresent(token -> refreshTokenService.deleteByUserId(token.getUser().getId()));

        return ResponseEntity.ok("Logged out successfully");
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<String> handleRuntimeException(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage());
    }
}

