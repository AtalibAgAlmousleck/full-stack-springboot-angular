package com.atalibdev.jwt;

import com.atalibdev.constant.SecurityConstant;
import com.atalibdev.entity.HttpResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;

import static com.atalibdev.constant.SecurityConstant.FORBIDDEN_MESSAGE;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

// take the control of the extends interface
@Component
public class JwtAuthenticationEntryPoint extends Http403ForbiddenEntryPoint {
    // Always returns a 403 error code to the client
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException arg2) throws IOException {
        HttpResponse httpResponse = new HttpResponse(
                FORBIDDEN.value(), FORBIDDEN,
                FORBIDDEN.getReasonPhrase().toUpperCase(),
                FORBIDDEN_MESSAGE);
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(FORBIDDEN.value());
        OutputStream output = response.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(output, httpResponse);
        output.flush();
    }
}
