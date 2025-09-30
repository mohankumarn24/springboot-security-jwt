package net.projectsync.security.jwt.configuration;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import net.projectsync.security.jwt.entity.User;
import net.projectsync.security.jwt.repository.UserRepository;

@Configuration
public class CreateUsers {

	@Bean
	CommandLineRunner init(UserRepository userRepo, PasswordEncoder encoder) {
		return args -> {
			if (userRepo.findByUsername("admin").isEmpty()) {
				User admin = new User();
				admin.setUsername("admin");
				admin.setPassword(encoder.encode("password"));
				admin.setRole("ROLE_ADMIN");
				userRepo.save(admin);
			}

			if (userRepo.findByUsername("user").isEmpty()) {
				User user = new User();
				user.setUsername("user");
				user.setPassword(encoder.encode("password"));
				user.setRole("ROLE_USER");
				userRepo.save(user);
			}
		};
	}

}
