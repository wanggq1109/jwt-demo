package cn.ningxy.jwtdemo.sys.auth.mapper;

import cn.ningxy.jwtdemo.sys.auth.entity.RefreshToken;
import org.apache.ibatis.annotations.*;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author ningxy
 * @date 2019/02/26
 */
@Mapper
@Repository
public interface RefreshTokenMapper {

    @Select("SELECT * FROM sys_refresh_token WHERE token = #{token} LIMIT 1")
    RefreshToken selectRefreshTokenByToken(@Param("token") String token);

    @Insert("REPLACE INTO sys_refresh_token (" +
            "`id`, " +
            "`created_at`, " +
            "`expiry_date`, " +
            "`refresh_count`, " +
            "`token`, " +
            "`user_id`, " +
            "`user_device_id`) " +
            "VALUES (" +
            "#{id}, " +
            "#{createdAt}, " +
            "#{expiryDate}, " +
            "#{refreshCount}, " +
            "#{token}, " +
            "#{userId}, " +
            "#{userDeviceId})"
    )
    @Options(useGeneratedKeys=true)
    int insertRefreshToken(RefreshToken refreshToken);

    @Delete("DELETE FROM sys_refresh_token WHERE id = #{id} LIMIT 1")
    int deleteRefreshTokenById (@Param("id") Long id);

    @Update("UPDATE sys_refresh_token SET refresh_count = refresh_count + 1 WHERE token = #{token} LIMIT 1")
    int increaseRefreshCount(@Param("token") String token);
}
