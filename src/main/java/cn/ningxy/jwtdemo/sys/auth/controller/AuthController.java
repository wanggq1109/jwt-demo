package cn.ningxy.jwtdemo.sys.auth.controller;

import cn.ningxy.jwtdemo.sys.auth.entity.JwtUser;
import cn.ningxy.jwtdemo.sys.auth.service.AuthService;
import cn.ningxy.jwtdemo.sys.auth.component.IpUtil;
import cn.ningxy.jwtdemo.sys.user.po.SysUser;
import cn.ningxy.jwtdemo.sys.user.service.SysUserService;
import com.alibaba.fastjson.JSON;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.time.LocalDateTime;

/**
 * @author ningxy
 * @date 2019/02/02
 */
@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthController {
    @Autowired
    private SysUserService userService;

    @Autowired
    private AuthService authService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/register")
    public String registerUser(@Valid @RequestBody SysUser user) {
        // 记得注册的时候把密码加密一下
        user.setPwd(bCryptPasswordEncoder.encode(user.getPwd()));
//        user.setRole("ROLE_USER");
        userService.insertSelective(user);
        return user.toString();
    }

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public String login(@Valid @RequestBody JwtUser loginUser, HttpServletResponse response, HttpServletRequest request) {
        JwtUser user = authService.login(loginUser);
        final String ipAddr = IpUtil.getClientIpAddress(request);
        authService.saveLoginInfo(user.getId(), ipAddr, LocalDateTime.now());
        log.info("用户[" + loginUser.getUsername() + "]登陆成功");
        response.setHeader("Authorization", user.getAccessToken());
        return JSON.toJSONString(user);
    }

    @RequestMapping(value = "/refreshToken", method = RequestMethod.POST)
    public String refreshToken(@RequestParam("refreshToken") String expiredToken) {
         return authService.refreshToken(expiredToken);
    }
}
