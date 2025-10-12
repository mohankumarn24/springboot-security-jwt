package net.projectsync.security.jwt.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "security.cookie")
public class CookieProperties {

	private Cookie refresh = new Cookie();
	private Cookie csrf = new Cookie();

	public static class Cookie {
		private String name;
		private String path;
		private long maxAgeSeconds;

		// Getters and setters
		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public String getPath() {
			return path;
		}

		public void setPath(String path) {
			this.path = path;
		}

		public long getMaxAgeSeconds() {
			return maxAgeSeconds;
		}

		public void setMaxAgeSeconds(long maxAgeSeconds) {
			this.maxAgeSeconds = maxAgeSeconds;
		}
	}

	// Getter/setter names should follow JavaBean conventions (getRefresh() / setRefresh()), not custom names like getRefreshCookie()
	
	public Cookie getRefresh() {
		return refresh;
	}

	public void setRefresh(Cookie refresh) {
		this.refresh = refresh;
	}

	public Cookie getCsrf() {
		return csrf;
	}

	public void setCsrf(Cookie csrf) {
		this.csrf = csrf;
	}
}
