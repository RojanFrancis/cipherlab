package com.rojan.cipherlab;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Boots the full application context against the H2-backed {@code dev} profile
 * so integration tests never require an external PostgreSQL instance.
 * Flyway migrations still execute, which means schema errors fail the build.
 */
@SpringBootTest
@ActiveProfiles("dev")
class CipherLabApplicationTests {

	@Test
	void contextLoads() {
	}

}
