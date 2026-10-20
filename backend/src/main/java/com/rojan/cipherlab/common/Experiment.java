package com.rojan.cipherlab.common;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/**
 * A recorded lab experiment run (spec §8): which primitive was exercised and
 * a short summary of the outcome. The summary holds <b>metadata</b> only —
 * plaintexts, keys and full ciphertexts are never persisted here; the value
 * of the record is the learning trail, not the payload.
 */
@Entity
@Table(name = "experiments")
public class Experiment {

    @Id
    @Column(name = "id")
    private UUID id;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "experiment_type", nullable = false, length = 64)
    private String experimentType;

    @Column(name = "result_summary", length = 2000)
    private String resultSummary;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void prePersist() {
        if (id == null) {
            id = UUID.randomUUID();
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now(java.time.ZoneOffset.UTC);
        }
    }

    public UUID getId() {
        return id;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getExperimentType() {
        return experimentType;
    }

    public String getResultSummary() {
        return resultSummary;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public static Experiment of(UUID userId, String experimentType, String resultSummary) {
        Experiment experiment = new Experiment();
        experiment.id = UUID.randomUUID();
        experiment.userId = userId;
        experiment.experimentType = experimentType;
        experiment.resultSummary = resultSummary;
        return experiment;
    }
}
