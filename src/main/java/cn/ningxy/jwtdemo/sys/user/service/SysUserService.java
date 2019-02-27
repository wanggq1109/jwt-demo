package cn.ningxy.jwtdemo.sys.user.service;

import cn.ningxy.jwtdemo.sys.user.po.SysUser;
import cn.ningxy.jwtdemo.sys.user.po.SysUserExample;

import java.util.List;

/**
 * @author: ningxy
 * @create: 2019/01/17
 */
public interface SysUserService {
    int insertSelective(SysUser record);

    List<SysUser> selectByExample(SysUserExample example);
}
