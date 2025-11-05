package net.projectsync.security.jwt.configuration;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import net.projectsync.security.jwt.entity.User;
import net.projectsync.security.jwt.model.Role;
import net.projectsync.security.jwt.repository.UserRepository;

@Configuration
//@Profile("dev") // Only runs in 'dev' profile
public class CreateUsersStartUp {

	@Bean
	CommandLineRunner init(UserRepository userRepo, PasswordEncoder encoder) {

		return new CommandLineRunner() {

			@Override
			public void run(String... args) throws Exception {
				if (userRepo.findByUsername("admin").isEmpty()) {
					User admin = new User();
					admin.setUsername("admin");
					admin.setPassword(encoder.encode("India@123"));
					admin.setRole(Role.ADMIN);
					userRepo.save(admin);
				}

				if (userRepo.findByUsername("user").isEmpty()) {
					User user = new User();
					user.setUsername("user");
					user.setPassword(encoder.encode("India@123"));
					user.setRole(Role.USER);
					userRepo.save(user);
				}
			}
		};
	}
}

/*
package net.projectsync.security.jwt.configuration;

import com.example.demo.model.Role;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.boot.CommandLineRunner;

@Configuration
// @Profile("dev")  // Only active in 'dev' profile
public class CreateUsersStartUp {

    @Value("${app.default.admin.password}")
    private String adminPassword;

    @Value("${app.default.user.password}")
    private String userPassword;

    @Bean
    CommandLineRunner init(UserRepository userRepo, PasswordEncoder encoder) {
        return args -> {
            userRepo.findByUsername("admin").orElseGet(() -> {
                User admin = new User();
                admin.setUsername("admin");
                admin.setPassword(encoder.encode(adminPassword));
                admin.setRole(Role.ADMIN);
                return userRepo.save(admin);
            });

            userRepo.findByUsername("user").orElseGet(() -> {
                User user = new User();
                user.setUsername("user");
                user.setPassword(encoder.encode(userPassword));
                user.setRole(Role.USER);
                return userRepo.save(user);
            });
        };
    }
}
*/