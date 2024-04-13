package com.xopuntech.authentication.inti;

import com.xopuntech.authentication.models.Role;
import com.xopuntech.authentication.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class SystemDataLoader implements CommandLineRunner {

    private final RoleRepository roleRepository;

    public SystemDataLoader(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public void run(String... args) throws Exception {
        // Insert roles if they don't exist
        if (!roleRepository.findByName("USER").isPresent()) {
            Role userRole = Role.builder().name("USER").build();
            roleRepository.save(userRole);
        }

        if (!roleRepository.findByName("ADMIN").isPresent()) {
            Role adminRole = Role.builder().name("ADMIN").build();
            roleRepository.save(adminRole);
        }
    }
}
