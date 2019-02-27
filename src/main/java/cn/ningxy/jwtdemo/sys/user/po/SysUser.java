package cn.ningxy.jwtdemo.sys.user.po;

import cn.ningxy.jwtdemo.sys.auth.component.RoleName;
import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SysUser implements Serializable {
    protected Long id;

    @JSONField(serialize = false)
    protected Byte roleId;

    protected String username;

    @JSONField(serialize = false)
    protected String pwd;

    protected String phone;

    protected String email;

    protected String firstName;

    protected String lastName;

    protected LocalDateTime lastLoginTime;

    protected String lastLoginIp;

    protected LocalDateTime lastPasswordReset;

    protected Boolean deleted;

    protected Boolean enabled;

    protected RoleName roleName;

    private static final long serialVersionUID = 1274068211542875414L;

    public RoleName getRoleName() {
        if (null == roleName) {
            setRoleName(RoleName.values()[roleId]);
        }
        return roleName;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", id=").append(id);
        sb.append(", roleId=").append(roleId);
        sb.append(", username=").append(username);
        sb.append(", pwd=").append(pwd);
        sb.append(", phone=").append(phone);
        sb.append(", email=").append(email);
        sb.append(", firstName=").append(firstName);
        sb.append(", lastName=").append(lastName);
        sb.append(", lastLoginTime=").append(lastLoginTime);
        sb.append(", lastLoginIp=").append(lastLoginIp);
        sb.append(", lastPasswordReset=").append(lastPasswordReset);
        sb.append(", deleted=").append(deleted);
        sb.append(", enabled=").append(enabled);
        sb.append(", serialVersionUID=").append(serialVersionUID);
        sb.append("]");
        return sb.toString();
    }
}