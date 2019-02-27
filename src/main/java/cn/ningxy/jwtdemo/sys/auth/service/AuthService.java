package cn.ningxy.jwtdemo.sys.auth.service;

import cn.ningxy.jwtdemo.sys.auth.entity.JwtUser;
import cn.ningxy.jwtdemo.sys.user.po.SysUser;

import java.time.LocalDateTime;

/**
 * @author ningxy
 * @date 2019/02/11
 */
public interface AuthService {
    JwtUser login(JwtUser sysUser);

    void saveLoginInfo(Long userId, String ipAddr, LocalDateTime loginTime);

    String refreshToken(String expiredToken);
}
