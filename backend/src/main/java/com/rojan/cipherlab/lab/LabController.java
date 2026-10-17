package com.rojan.cipherlab.lab;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.rojan.cipherlab.lab.dto.LabRequests;
import com.rojan.cipherlab.lab.dto.LabResponses;

import jakarta.validation.Valid;

/**
 * Crypto Lab endpoints (spec §5, column 2).
 *
 * <p><b>These are educational demonstrations.</b> They are never invoked by
 * the secure messaging client; the messaging path performs encryption
 * strictly in the browser with Web Crypto. The lab routes are publicly
 * readable because they hold no user data — every other route in the
 * application requires authentication (see {@code SecurityConfig}).
 *
 * <p>Controller concerns only: HTTP binding + validation delegation.
 * All behavior lives in {@link LabService}.
 */
@RestController
@RequestMapping("/api/v1/lab")
public class LabController {

    private final LabService labService;

    public LabController(LabService labService) {
        this.labService = labService;
    }

    @PostMapping("/aes/encrypt")
    public LabResponses.Encrypt encrypt(@Valid @RequestBody LabRequests.Encrypt request) {
        return labService.encrypt(request);
    }

    @PostMapping("/aes/decrypt")
    public LabResponses.Decrypt decrypt(@Valid @RequestBody LabRequests.Decrypt request) {
        return labService.decrypt(request);
    }

    @PostMapping("/hash")
    public LabResponses.Hash hash(@Valid @RequestBody LabRequests.Hash request) {
        return labService.hash(request);
    }

    @PostMapping("/hmac")
    public LabResponses.Hmac hmac(@Valid @RequestBody LabRequests.Hmac request) {
        return labService.hmac(request);
    }

    @PostMapping("/diffie-hellman")
    public LabResponses.DiffieHellman diffieHellman(@Valid @RequestBody LabRequests.DiffieHellman request) {
        return labService.diffieHellman(request);
    }
}