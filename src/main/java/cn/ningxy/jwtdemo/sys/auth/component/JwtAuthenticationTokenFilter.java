package cn.ningxy.jwtdemo.sys.auth.component;

import cn.ningxy.jwtdemo.sys.auth.component.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author ningxy
 * @date 2019/01/17
 */
@Slf4j
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Value("${jwt.header}")
    private String token_header;

    private static final String AUTH_TOKEN_START = "Bearer ";

    @Resource
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
        final String token = getTokenFromHeader(httpServletRequest);
        final String username;

        try {
            username = jwtUtil.getUsername(token);
            if (null != username && null == SecurityContextHolder.getContext().getAuthentication()) {
                UserDetails userDetails = jwtUtil.getJwtUser(token);

                if (jwtUtil.validateToken(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                    log.info("authorizated user '{}', setting security context", username);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (Exception e) {
            log.info("[Invalid Token] " + e.getMessage());
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);

    }

    private String getTokenFromHeader(HttpServletRequest request) {
        final String authToken = request.getHeader(this.token_header);
        if (StringUtils.startsWith(authToken, AUTH_TOKEN_START)) {
            return StringUtils.substring(authToken, AUTH_TOKEN_START.length());
        } else {
            return null;
        }
    }
}
