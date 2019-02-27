package cn.ningxy.jwtdemo.sys.auth.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Date;

/**
 * @author ningxy
 * @date 2019/02/26
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    private Long id;

    private String token;

    private Long userId;

    private Long userDeviceId;

    private Integer refreshCount;

    private Date expiryDate;

    private Date createdAt;

    public void incrementRefreshCount() {
        this.refreshCount = this.refreshCount + 1;
    }

}
