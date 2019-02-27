package cn.ningxy.jwtdemo.sys.auth.service.impl;

import cn.ningxy.jwtdemo.sys.auth.entity.JwtUser;
import cn.ningxy.jwtdemo.sys.auth.entity.RefreshToken;
import cn.ningxy.jwtdemo.sys.auth.mapper.RefreshTokenMapper;
import cn.ningxy.jwtdemo.sys.auth.service.AuthService;
import cn.ningxy.jwtdemo.sys.auth.component.JwtUtil;
import cn.ningxy.jwtdemo.sys.user.mapper.SysUserMapper;
import cn.ningxy.jwtdemo.sys.user.po.SysUser;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;

/**
 * AuthServiceImpl
 *
 * @author ningxy
 * @date 2019/02/11
 */
@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private SysUserMapper sysUserMapper;
    @Autowired
    private RefreshTokenMapper refreshTokenMapper;

    @Override
    public JwtUser login(JwtUser jwtUser) {
        final UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                jwtUser.getUsername(),
                jwtUser.getPassword(),
                new ArrayList<>()
        );
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        jwtUser.setAuthorities(authentication.getAuthorities());
        JwtUser user = (JwtUser) authentication.getPrincipal();
        final String accessToken = jwtUtil.generateAccessToken(user);
        final RefreshToken refreshToken = jwtUtil.generateRefreshToken(user);
        refreshToken.setRefreshCount(0);
        refreshToken.setUserDeviceId(0L);

        refreshTokenMapper.insertRefreshToken(refreshToken);

        user.setAccessToken(accessToken);
        user.setRefreshToken(refreshToken.getToken());
        return user;
    }

    @Override
    public void saveLoginInfo(Long userId, String ipAddr, LocalDateTime loginTime) {
        SysUser user = SysUser.builder()
                .id(userId)
                .lastLoginIp(ipAddr)
                .lastLoginTime(loginTime)
                .build();
        sysUserMapper.updateByPrimaryKeySelective(user);
    }

    @Override
    public String refreshToken(String refreshToken) {
        String newToken;

        RefreshToken refreshTokenObj = refreshTokenMapper.selectRefreshTokenByToken(refreshToken);
        if (null != refreshTokenObj) {
            newToken = jwtUtil.refreshToken(refreshToken);
            refreshTokenMapper.increaseRefreshCount(refreshToken);
        } else {
            newToken = null;
        }

        return newToken;
    }
}
