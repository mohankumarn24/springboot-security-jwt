package net.projectsync.security.jwt.actuators;

import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.stereotype.Component;
import java.util.HashMap;
import java.util.Map;

// Add this line in properties file --> management.endpoints.web.exposure.include=custom-info
@Component
@Endpoint(id = "custom-info") // this will appear at /actuator/custom-info
public class CustomInfoEndpoint {

    @ReadOperation
    public Map<String, Object> getCustomInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("appName", "ProjectSync JWT Service");
        info.put("version", "1.0.0");
        info.put("uptime", System.currentTimeMillis()); // example info
        info.put("status", "running");
        return info;
    }
}

/*
| Endpoint    | Purpose                                     |
| ----------- | ------------------------------------------- |
| `/health`   | App health (UP/DOWN/OUT_OF_SERVICE)         |
| `/info`     | App info (version, build, custom)           |
| `/env`      | Spring environment properties               |
| `/beans`    | List of beans in Spring context             |
| `/metrics`  | JVM, memory, GC, datasource, custom metrics |
| `/mappings` | URL mappings in controllers                 |
| `/loggers`  | Adjust logging levels at runtime            |
*/

/*
 * TODO: Also know info about custom metrics and Micrometer (See: OneNote)
 * 
 * What is Micrometer?
 * 	- Micrometer is the metrics library Spring Boot uses under the hood (via spring-boot-starter-actuator).
 * 	- It allows you to instrument your app and expose metrics to monitoring systems like Prometheus, Datadog, Graphite, etc..
 * 	- Actuator endpoints like /actuator/metrics already expose built-in metrics (CPU, memory, HTTP requests).
 * 	- You can add custom counters, gauges, timers for application-specific things.
 */