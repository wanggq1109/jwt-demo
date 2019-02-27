package cn.ningxy.jwtdemo.sys.auth.entity;

import cn.ningxy.jwtdemo.sys.user.po.SysUser;
import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.BeanUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * @author ningxy
 * @date 2019/01/17
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtUser extends SysUser implements UserDetails {

    @JSONField(serialize = false)
    private Collection<? extends GrantedAuthority> authorities;

    private String accessToken;
    private String refreshToken;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.pwd;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    /**
     * 账号是否未过期
     *
     * @return true: 未过期; false: 已过期
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 账号是否未被锁定
     *
     * @return true: 未被锁定; false: 已被锁定
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 账号凭证是否未过期
     *
     * @return true: 未过期; false: 已过期
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 账号是否启用
     *
     * @return true: 启用; false: 未启用
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public static JwtUser create(SysUser sysUser) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(sysUser.getRoleName().name()));
        JwtUser jwtUser = new JwtUser();
        jwtUser.setAuthorities(authorities);
        BeanUtils.copyProperties(sysUser, jwtUser);
        return jwtUser;
    }
}
