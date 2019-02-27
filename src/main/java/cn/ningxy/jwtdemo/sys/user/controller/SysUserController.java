package cn.ningxy.jwtdemo.sys.user.controller;

import cn.ningxy.jwtdemo.sys.user.po.SysUserExample;
import cn.ningxy.jwtdemo.sys.user.service.SysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * @author ningxy
 * @date 2019/02/24
 */
@RestController
@RequestMapping("/user")
public class SysUserController {

    @Autowired
    SysUserService sysUserService;

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = "/", method = RequestMethod.GET)
    public List selectUser() {
        SysUserExample userExample = new SysUserExample();
        return sysUserService.selectByExample(userExample);
    }
}
