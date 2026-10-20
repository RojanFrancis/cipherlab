package com.rojan.cipherlab.common;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Writes audit rows, with the <b>timing</b> chosen to match the kind of
 * event — the distinction that makes the trail reliable.
 *
 * <p><b>Why not just {@code REQUIRES_NEW} everywhere?</b> That was the first
 * attempt and it broke registration outright. A {@code REQUIRES_NEW} write
 * suspends the caller's transaction and opens a second one on a separate
 * connection; the {@code USER_REGISTERED} row references a {@code users} row
 * that the suspended transaction has <em>not committed yet</em>, so the
 * foreign key fails: {@code Referential integrity constraint violation}
 * (caught by {@code AuditTrailTest} before it shipped).
 *
 * <p>So there are two entry points:
 * <ul>
 *   <li>{@link #record} — for events that occur <b>alongside a successful
 *       change</b> (registration, key published, session activated). It
 *       defers the write to <b>after commit</b>, so the referenced rows are
 *       visible and, if the business transaction rolls back, no phantom
 *       audit row claims the event happened.</li>
 *   <li>{@link #recordSecurityEvent} — for events that occur <b>because a
 *       request was rejected</b> (replay attempt, failed login). These must
 *       survive the caller's rollback, so they write immediately in their
 *       own transaction. That is safe because the entities they reference
 *       (the existing user, the existing session) were committed earlier.</li>
 * </ul>
 *
 * <p>Audit failures never break the flow they describe: a write that throws
 * is logged and dropped. Losing an audit row is bad; turning a successful
 * login into a 500 because the audit table hiccuped is worse. (Documented
 * trade-off for the threat model: someone who can fault the audit table
 * reduces observability, but cannot bypass authentication.)
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditEventRepository auditEventRepository;
    private final TransactionTemplate newTransactionTemplate;

    public AuditService(AuditEventRepository auditEventRepository,
                        org.springframework.transaction.PlatformTransactionManager transactionManager) {
        this.auditEventRepository = auditEventRepository;
        this.newTransactionTemplate = new TransactionTemplate(transactionManager);
        this.newTransactionTemplate.setPropagationBehavior(TransactionTemplate.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * Audit an event that accompanies a successful business change. Written
     * after the surrounding transaction commits.
     */
    public void record(UUID actorId, String eventType, String resourceId) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    // A fresh transaction is required here: the surrounding
                    // one has already completed, so the thread-bound
                    // EntityManager can no longer host a write.
                    newTransactionTemplate.executeWithoutResult(status -> write(actorId, eventType, resourceId));
                }
            });
        } else {
            write(actorId, eventType, resourceId);
        }
    }

    /**
     * Audit a security event that is <em>caused by</em> a rejection — the
     * caller is about to roll back, and this row must outlive it.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordSecurityEvent(UUID actorId, String eventType, String resourceId) {
        write(actorId, eventType, resourceId);
    }

    private void write(UUID actorId, String eventType, String resourceId) {
        try {
            auditEventRepository.save(AuditEvent.of(actorId, eventType, resourceId));
        } catch (RuntimeException e) {
            log.warn("Audit write failed for {} (continuing): {}", eventType, e.getMessage());
        }
    }
}
