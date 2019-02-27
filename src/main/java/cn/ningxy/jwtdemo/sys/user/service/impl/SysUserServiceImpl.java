package cn.ningxy.jwtdemo.sys.user.service.impl;

import cn.ningxy.jwtdemo.sys.auth.entity.JwtUser;
import cn.ningxy.jwtdemo.sys.user.mapper.SysUserMapper;
import cn.ningxy.jwtdemo.sys.user.po.SysUser;
import cn.ningxy.jwtdemo.sys.user.po.SysUserExample;
import cn.ningxy.jwtdemo.sys.user.service.SysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @author ningxy
 * @create 2019/01/17
 */
@Service
public class SysUserServiceImpl implements SysUserService, UserDetailsService {
    @Autowired
    SysUserMapper sysUserMapper;

    @Override
    public int insertSelective(SysUser sysUser) {
        return sysUserMapper.insertSelective(sysUser);
    }

    @Override
    public List<SysUser> selectByExample(SysUserExample sysUserExample) {
        return sysUserMapper.selectByExample(sysUserExample);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser sysUser = sysUserMapper.selectByUsername(username);

        if (sysUser == null) {
            throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
        } else {
            return JwtUser.create(sysUser);
        }
    }
}
