package com.rojan.cipherlab.crypto.mitm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.rojan.cipherlab.common.InvalidRequestException;

class MitmSimulationTest {

    private final MitmSimulation sim = new MitmSimulation();

    @Test
    @DisplayName("unauthenticated mode: Mallory reads everything, substitution goes undetected")
    void unauthenticatedSucceedsForMallory() {
        var s = sim.simulate("unauthenticated");
        assertEquals("unauthenticated", s.mode());
        assertTrue(s.malloryCanRead());
        assertFalse(s.substitutionDetected());
        // Both parties' 'shared' secrets terminate at Mallory:
        assertEquals("no shared secret exists", s.sharedSecrets().get("alice ↔ bob (intended)"));
        assertNotNull(s.sharedSecrets().get("alice ↔ mallory"));
        assertNotNull(s.sharedSecrets().get("bob ↔ mallory"));
        assertFalse(s.sharedSecrets().get("alice ↔ mallory")
                .equals(s.sharedSecrets().get("bob ↔ mallory")), "two DISTINCT substituted sessions");
        assertEquals(3, s.participants().size());
        String steps = String.join("\n", s.steps());
        assertTrue(steps.contains("intercepts"), "narrative must show the interception");
        assertTrue(steps.contains("attacks are best prevented") || steps.contains("problem"),
                "must conclude why the attack worked");
    }

    @Test
    @DisplayName("authenticated mode: same attack trips the signature check, Mallory reads nothing")
    void authenticatedRejectsSubstitution() {
        var s = sim.simulate("authenticated");
        assertEquals("authenticated", s.mode());
        assertFalse(s.malloryCanRead());
        assertTrue(s.substitutionDetected());
        String steps = String.join("\n", s.steps());
        assertTrue(steps.contains("FAILS"), "signature verification must visibly fail");
        assertTrue(steps.contains("registered public key"),
                "must reference identity binding, not just 'a signature'");
        // The comparison the whole experiment exists for:
        var weak = sim.simulate("unauthenticated");
        assertTrue(weak.malloryCanRead() && !s.malloryCanRead(),
                "same attack: succeeds without authentication, fails with it");
    }

    @Test
    @DisplayName("unknown simulation modes are refused — no arbitrary parameters in the attack lab")
    void invalidModeRejected() {
        InvalidRequestException ex = assertThrows(InvalidRequestException.class,
                () -> sim.simulate("real-network"));
        assertEquals("INVALID_MODE", ex.getCode());
    }

    @Test
    @DisplayName("simulation runs on toy values only — never accepts network/input parameters")
    void simulationIsInputFree() {
        // The API takes ONLY a mode string: there is structurally no way to
        // point this at a real host, port, or user.
        var s = sim.simulate(MitmSimulation.UNAUTHENTICATED);
        assertTrue(s.securityNote().contains("toy values only"),
                "note must bound the simulation to the lab's toy values");
    }
}