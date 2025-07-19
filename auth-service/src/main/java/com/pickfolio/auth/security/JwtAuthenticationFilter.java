package com.pickfolio.auth.security;

import com.pickfolio.auth.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final AuthenticationEntryPoint jwtAuthEntryPoint;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService, AuthenticationEntryPoint jwtAuthEntryPoint) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.jwtAuthEntryPoint = jwtAuthEntryPoint;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7); // Remove "Bearer " prefix
        final String usernameFromToken = jwtService.extractUsernameFromAccessToken(token);

        try {
            if (usernameFromToken == null) {
                throw new AuthenticationCredentialsNotFoundException("Username not found in token");
            }

            UserDetails userDetails = userDetailsService.loadUserByUsername(usernameFromToken);

            if (!jwtService.validateAccessToken(token, userDetails.getUsername())) {
                throw new BadCredentialsException("Invalid access token");
            }

            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (UsernameNotFoundException e) {
            logger.error("Access token might be tampered with: User not found: " + usernameFromToken);
            jwtAuthEntryPoint.commence(request, response, new AuthenticationCredentialsNotFoundException("Access token malformed: user not found", e));
            return;
        } catch (BadCredentialsException | AuthenticationCredentialsNotFoundException e) {
            logger.error(e.getMessage());
            jwtAuthEntryPoint.commence(request, response, e);
            return;
        } catch (Exception e) {
            logger.error("Unexpected error during authentication: ", e);
            jwtAuthEntryPoint.commence(request, response, new BadCredentialsException("Unexpected error", e));
            return;
        }

        filterChain.doFilter(request, response);
    }
}
