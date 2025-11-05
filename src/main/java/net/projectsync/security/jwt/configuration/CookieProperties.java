package net.projectsync.security.jwt.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "security.cookie")
public class CookieProperties {

	public static class Cookie {
		private String name;
		private String path;
		private long maxAgeSeconds;

		// Getters and setters
		public String getName() { return name; }
		public String getPath() { return path; }
		public long getMaxAgeSeconds() { return maxAgeSeconds; }		
		public void setName(String name) { this.name = name; }
		public void setPath(String path) { this.path = path; }
		public void setMaxAgeSeconds(long maxAgeSeconds) { this.maxAgeSeconds = maxAgeSeconds; }
	}
	
	private Cookie refresh = new Cookie();
	private Cookie csrf = new Cookie();

	// Getter/setter names should follow JavaBean conventions (getRefresh() / setRefresh()), not custom names like getRefreshCookie()
	public Cookie getRefresh() { return refresh; }
	public Cookie getCsrf() { return csrf; }
	public void setRefresh(Cookie refresh) { this.refresh = refresh; }
	public void setCsrf(Cookie csrf) { this.csrf = csrf; }
}


/*
// slightly cleaner/refactored version using Lombok to reduce boilerplate code
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "security.cookie")
@Data
public class CookieProperties {

    @Data
    public static class Cookie {
        private String name;
        private String path;
        private long maxAgeSeconds;
    }

    private Cookie refresh = new Cookie();
    private Cookie csrf = new Cookie();
}
*/