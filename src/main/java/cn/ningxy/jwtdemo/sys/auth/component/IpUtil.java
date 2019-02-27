package cn.ningxy.jwtdemo.sys.auth.component;

import javax.servlet.http.HttpServletRequest;
import java.util.StringTokenizer;

/**
 * @author ningxy
 * @date 2019/02/15
 */
public class IpUtil {
    public static String getClientIpAddress(HttpServletRequest request) {
        String xForwardedForHeader = request.getHeader("X-Forwarded-For");
        if (xForwardedForHeader == null) {
            return request.getRemoteAddr();
        } else {
            // As of https://en.wikipedia.org/wiki/X-Forwarded-For
            // The general format of the field is: X-Forwarded-For: client, proxy1, proxy2 ...
            // we only want the client
            return new StringTokenizer(xForwardedForHeader, ",").nextToken().trim();
        }
    }
}
