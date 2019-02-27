package cn.ningxy.jwtdemo.sys.auth.component;

import cn.ningxy.jwtdemo.sys.auth.entity.JwtUser;
import cn.ningxy.jwtdemo.sys.auth.entity.RefreshToken;
import com.alibaba.fastjson.JSON;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClock;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.lang.reflect.Array;
import java.util.*;
import java.util.function.Function;

/**
 * @author ningxy
 * @date 2019/01/17
 */
@Getter
@Component
public class JwtUtil {
    public static final String ROLE_REFRESH_TOKEN = "ROLE_REFRESH_TOKEN";

    private static final String CLAIM_KEY_USER_ID = "user_id";
    private static final String CLAIM_KEY_AUTHORITIES = "scope";
    private static final String CLAIM_KEY_ACCOUNT_ENABLED = "enabled";
    private static final String CLAIM_KEY_ACCOUNT_NON_LOCKED = "non_locked";
    private static final String CLAIM_KEY_ACCOUNT_NON_EXPIRED = "non_expired";

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access_token.expiration}")
    private Long access_token_expiration;

    @Value("${jwt.refresh_token.expiration}")
    private Long refresh_token_expiration;

    private Clock clock = DefaultClock.INSTANCE;

    private final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS256;

    public JwtUser getJwtUser(String token) {
        JwtUser user;
        try {
            final Claims claims = getAllClaimsFromToken(token);
            final Long userId = getUserId(token);
            final String username = getUsername(token);
            final Collection<? extends GrantedAuthority> authorities = getAuthorities(claims);
//            final Collection<? extends GrantedAuthority> authorities = (Collection<? extends GrantedAuthority>) claims.get(CLAIM_KEY_AUTHORITIES);
            boolean account_enabled = (Boolean) claims.get(CLAIM_KEY_ACCOUNT_ENABLED);
            boolean account_non_locked = (Boolean) claims.get(CLAIM_KEY_ACCOUNT_NON_LOCKED);
            boolean account_non_expired = (Boolean) claims.get(CLAIM_KEY_ACCOUNT_NON_EXPIRED);
            user = new JwtUser();
            user.setId(userId);
            user.setUsername(username);
            user.setAuthorities(authorities);
            user.setEnabled(account_enabled);
        } catch (Exception e) {
            user = null;
        }

        return user;

    }

    /**
     * 用户ID
     *
     * @param token
     * @return
     */
    public Long getUserId(String token) {
        Long id = getAllClaimsFromToken(token).get(CLAIM_KEY_USER_ID, Long.class);
        return id;
    }

    /**
     * 用户名
     *
     * @param token
     * @return
     */
    public String getUsername(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * 签发时间
     *
     * @param token
     * @return
     */
    public Date getIssuedAt(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    /**
     * 过期时间
     *
     * @param token
     * @return
     */
    public Date getExpirationDate(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public List<? extends GrantedAuthority> getAuthorities(Claims claims) {
        List<String> roles = (List<String>) claims.get(CLAIM_KEY_AUTHORITIES);
        List list = new ArrayList<>();
        for (String s : roles) {
            list.add(new SimpleGrantedAuthority(s));
        }
        return list;
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }

    private String generateToken(String subject, Map<String, Object> claims, long expiration) {

        final Date createdDate = clock.now();
        final Date expirationDate = calculateExpirationDate(expiration);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
//                .compressWith(CompressionCodecs.GZIP)
                .signWith(SIGNATURE_ALGORITHM, secret)
                .compact();
    }

    public String refreshToken(String token) {
        final Claims claims = getAllClaimsFromToken(token);
        ArrayList<String> authoritiesList = (ArrayList<String>) claims.get(CLAIM_KEY_AUTHORITIES);
        claims.put(CLAIM_KEY_AUTHORITIES, authoritiesList.get(0));
        return generateAccessToken(claims.getSubject(), claims);
    }

    public String generateAccessToken(UserDetails userDetails) {
        JwtUser user = (JwtUser) userDetails;
        Map<String, Object> claims = generateClaims(user);
        claims.put(CLAIM_KEY_AUTHORITIES, authoritiesToArray(user.getAuthorities()));
        return generateAccessToken(user.getUsername(), claims);
    }

    private String generateAccessToken(String subject, Map<String, Object> claims) {
        return generateToken(subject, claims, access_token_expiration);
    }

    public RefreshToken generateRefreshToken(UserDetails userDetails) {
        JwtUser user = (JwtUser) userDetails;
        Map<String, Object> claims = generateClaims(user);
        claims.put(CLAIM_KEY_AUTHORITIES, Arrays.asList(authoritiesToArray(user.getAuthorities()), JwtUtil.ROLE_REFRESH_TOKEN));

        final String token = generateRefreshToken(user.getUsername(), claims);

        return RefreshToken.builder()
                .token(token)
                .userId(getUserId(token))
                .createdAt(getIssuedAt(token))
                .expiryDate(getExpirationDate(token))
                .build();
    }

    private String generateRefreshToken(String subject, Map<String, Object> claims) {
        return generateToken(subject, claims, refresh_token_expiration);
    }

    public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
        final Date created = getIssuedAt(token);
        return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
                && (!isTokenExpired(token));
    }

    private Map<String, Object> generateClaims(JwtUser user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USER_ID, user.getId());
        claims.put(CLAIM_KEY_ACCOUNT_ENABLED, user.isEnabled());
        claims.put(CLAIM_KEY_ACCOUNT_NON_LOCKED, user.isAccountNonLocked());
        claims.put(CLAIM_KEY_ACCOUNT_NON_EXPIRED, user.isAccountNonExpired());
        return claims;
    }

    /**
     * 计算过期时间
     *
     * @param expiration token有效时间
     * @return 失效的具体时间
     */
    private Date calculateExpirationDate(long expiration) {
        return new Date(System.currentTimeMillis() + expiration * 1000);
    }

    /**
     * 验证token
     *
     * @param token
     * @param userDetails
     * @return
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        JwtUser user = (JwtUser) userDetails;
        final Long userId = getUserId(token);
        final String username = getUsername(token);
        final Date created = getIssuedAt(token);
//        final Date expiration = getExpirationDateFromToken(accessToken);
//        Date lastPasswordReset = null;
//        if (null != user.getLastPasswordReset()) {
//            lastPasswordReset = Date.from(user.getLastPasswordReset().atZone(ZoneId.of("Asia/Shanghai")).toInstant());
//        }
        return (userId.equals(user.getId())
                && username.equals(user.getUsername())
                && !isTokenExpired(token)
//                && !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
        );
    }

    /**
     * 检查token是否过期
     *
     * @param token
     * @return
     */
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDate(token);
        return expiration.before(clock.now());
    }

    /**
     * token创建后是否修改过密码
     *
     * @param created
     * @param lastPasswordReset
     * @return
     */
    private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }

    private List authoritiesToArray(Collection<? extends GrantedAuthority> authorities) {
        List<String> list = null;
        if (null != authorities) {
            list = new ArrayList<>();
            for (GrantedAuthority authority : authorities) {
                list.add(authority.getAuthority());
            }
        }
        return list;
    }
}
