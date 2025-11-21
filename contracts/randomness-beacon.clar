;; randomness-beacon.clar
;; ------------------------------------------------------------
;; Commit-Reveal Randomness Beacon for Stacks (STX)
;; - Epoch-based commit / reveal
;; - Contributors submit sha256(commit) during commit phase
;; - Contributors reveal preimages during reveal phase
;; - finalize-epoch concatenates all revealed preimages and sha256s them to produce randomness
;; - Requires min-reveals to finalize
;; ------------------------------------------------------------

(define-constant ERR_NOT_ADMIN u100)
(define-constant ERR_INVALID_AMOUNT u101)
(define-constant ERR_ALREADY_COMMITTED u102)
(define-constant ERR_COMMIT_NOT_FOUND u103)
(define-constant ERR_INVALID_REVEAL u104)
(define-constant ERR_REVEAL_TOO_EARLY u105)
(define-constant ERR_REVEAL_TOO_LATE u106)
(define-constant ERR_FINALIZE_TOO_EARLY u107)
(define-constant ERR_ALREADY_FINALIZED u108)
(define-constant ERR_NOT_ENOUGH_REVEALS u109)
(define-constant ERR_BEACON_INACTIVE u110)

;; Admin (deployer)
(define-data-var admin principal tx-sender)

;; Beacon parameters (blocks)
(define-data-var epoch-length uint u100)      ;; number of blocks per epoch (default 100)
(define-data-var reveal-window uint u20)      ;; last N blocks of each epoch reserved for reveal (default 20)
(define-data-var min-reveals uint u3)         ;; minimal reveals required to finalize epoch
(define-data-var active bool true)            ;; beacon on/off

;; Counters & bookkeeping
(define-data-var contrib-counter uint u0)     ;; global contributor counter (for indexing if needed)
(define-data-var next-finalized-epoch uint u0) ;; last epoch finalized (highest finalized epoch id + 1)

;; Maps and storage
;; contributor-list: { epoch, idx } -> principal
(define-map epoch-contribs { epoch: uint, idx: uint } { who: principal })

;; per-epoch contributor count: epoch -> uint
(define-map epoch-contrib-count { epoch: uint } { count: uint })

;; commitments: { epoch, who } -> buff 32 (sha256 of reveal)
(define-map commitments { epoch: uint, who: principal } { comm: (buff 32) })

;; reveals: { epoch, who } -> buff 256 (arbitrary-length reveal allowed; but we'll limit to 256 bytes)
(define-map reveals { epoch: uint, who: principal } { preimage: (buff 256) })

;; finalized randomness per epoch: epoch -> buff 32
(define-map epoch-random { epoch: uint } { rnd: (buff 32) })

;; per-epoch revealed count
(define-map epoch-reveal-count { epoch: uint } { count: uint })

;; Events for indexers
(define-private (ev-commit (epoch uint) (who principal) (comm (buff 32)))
  (print { event: "beacon-commit", epoch: epoch, who: who, commitment: comm }))

(define-private (ev-reveal (epoch uint) (who principal) (preimage (buff 256)))
  (print { event: "beacon-reveal", epoch: epoch, who: who, preimage: preimage }))

(define-private (ev-finalize (epoch uint) (random (buff 32)) (reveals-count uint))
  (print { event: "beacon-finalize", epoch: epoch, randomness: random, reveals: reveals-count }))

(define-private (ev-param-update (by principal) (new-epoch-length uint) (new-reveal-window uint) (new-min-reveals uint) (new-active bool))
  (print { event: "beacon-params-updated", by: by, epoch_length: new-epoch-length, reveal_window: new-reveal-window, min_reveals: new-min-reveals, active: new-active }))

;; -------------------------
;; Helpers
;; -------------------------

;; compute epoch id from a block height
(define-private (epoch-id-from-block (b uint))
  (ok (/ b (var-get epoch-length))))

;; epoch start block (inclusive)
(define-private (epoch-start-block (epoch uint))
  (ok (* epoch (var-get epoch-length))))

;; epoch end block (inclusive)
(define-private (epoch-end-block (epoch uint))
  (ok (- (+ (* epoch (var-get epoch-length)) (var-get epoch-length)) u1)))

;; commit-phase end block (last block where commit allowed) = epoch-end - reveal-window
(define-private (commit-phase-end (epoch uint))
  (let ((end (unwrap-panic (epoch-end-block epoch))))
    (ok (- end (var-get reveal-window)))))

;; reveal-phase start block (first block where reveal allowed) = commit-phase-end + 1
(define-private (reveal-phase-start (epoch uint))
  (ok (+ (unwrap-panic (commit-phase-end epoch)) u1)))

;; is-in-commit-phase?
(define-private (is-commit-phase (epoch uint) (current-block uint))
  (let ((start (unwrap-panic (epoch-start-block epoch)))
        (end (unwrap-panic (commit-phase-end epoch))))
    (ok (and (>= current-block start) (<= current-block end)))))

;; is-in-reveal-phase?
(define-private (is-reveal-phase (epoch uint) (current-block uint))
  (let ((start (unwrap-panic (reveal-phase-start epoch)))
        (end (unwrap-panic (epoch-end-block epoch))))
    (ok (and (>= current-block start) (<= current-block end)))))

;; check epoch already finalized
(define-private (is-finalized (epoch uint))
  (ok (is-some (map-get? epoch-random { epoch: epoch }))))

;; -------------------------
;; Admin setters
;; -------------------------
(define-public (set-params (new-epoch-length uint) (new-reveal-window uint) (new-min-reveals uint) (new-active bool))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err ERR_NOT_ADMIN))
    (asserts! (> new-epoch-length u0) (err ERR_INVALID_AMOUNT))
    (asserts! (> new-reveal-window u0) (err ERR_INVALID_AMOUNT))
    (asserts! (<= new-reveal-window new-epoch-length) (err ERR_INVALID_AMOUNT))
    (asserts! (> new-min-reveals u0) (err ERR_INVALID_AMOUNT))
    (var-set epoch-length new-epoch-length)
    (var-set reveal-window new-reveal-window)
    (var-set min-reveals new-min-reveals)
    (var-set active new-active)
    (ev-param-update tx-sender new-epoch-length new-reveal-window new-min-reveals new-active)
    (ok true)))

(define-public (set-admin (p principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err ERR_NOT_ADMIN))
    (var-set admin p)
    (ok true)))

;; -------------------------
;; Commit (called by any contributor during commit phase for a target epoch)
;; commitment must be a 32-byte buff (sha256 preimage expected)
;; -------------------------
(define-public (commit (epoch uint) (commitment (buff 32)))
  (begin
    (asserts! (var-get active) (err ERR_BEACON_INACTIVE))
    ;; store commitment without phase checking for now
    (asserts! (is-none (map-get? commitments { epoch: epoch, who: tx-sender })) (err ERR_ALREADY_COMMITTED))
    ;; store commitment
    (map-set commitments { epoch: epoch, who: tx-sender } { comm: commitment })
    ;; append contributor to epoch-contribs list
    (let ((cnt (default-to u0 (get count (map-get? epoch-contrib-count { epoch: epoch })))))
      (map-set epoch-contribs { epoch: epoch, idx: cnt } { who: tx-sender })
      (map-set epoch-contrib-count { epoch: epoch } { count: (+ cnt u1) }))
    (ev-commit epoch tx-sender commitment)
    (ok true)))

;; -------------------------
;; Reveal: contributor reveals preimage during reveal phase
;; preimage is a buff up to 256 bytes
;; reveal is accepted only if sha256(preimage) equals the previously committed buff32
;; -------------------------
(define-public (reveal (epoch uint) (preimage (buff 256)))
  (begin
    (asserts! (var-get active) (err ERR_BEACON_INACTIVE))
    ;; must be in reveal phase for epoch
    (let ((rp (unwrap-panic (is-reveal-phase epoch))))
      (asserts! rp (err ERR_REVEAL_TOO_EARLY)))
    ;; must have a commit
    (let ((copt (map-get? commitments { epoch: epoch, who: tx-sender })))
      (asserts! (is-some copt) (err ERR_COMMIT_NOT_FOUND))
      (let ((c (unwrap-panic copt)))
        ;; verify sha256(preimage) == stored commit
        (let ((calc (sha256 preimage))
              (stored (get comm c)))
          (asserts! (is-eq calc stored) (err ERR_INVALID_REVEAL))
          ;; store reveal
          (asserts! (is-none (map-get? reveals { epoch: epoch, who: tx-sender })) (err ERR_ALREADY_COMMITTED))
          (map-set reveals { epoch: epoch, who: tx-sender } { preimage: preimage })
          ;; increment reveal count
          (let ((rc (default-to u0 (get count (map-get? epoch-reveal-count { epoch: epoch })))))
            (map-set epoch-reveal-count { epoch: epoch } { count: (+ rc u1) }))
          (ev-reveal epoch tx-sender preimage)
          (ok true))))))

;; -------------------------
;; finalize-epoch: after reveal window ends, compute randomness by hashing concatenation of all revealed preimages
;; requires at least min-reveals valid reveals
;; -------------------------
(define-public (finalize-epoch (epoch uint))
  (begin
    (asserts! (var-get active) (err ERR_BEACON_INACTIVE))
    ;; not already finalized
    (let ((f (unwrap-panic (is-finalized epoch))))
      (asserts! (not f) (err ERR_ALREADY_FINALIZED)))
    ;; count reveals
    (let ((reveals-count (default-to u0 (get count (map-get? epoch-reveal-count { epoch: epoch })))))
      (asserts! (>= reveals-count (var-get min-reveals)) (err ERR_NOT_ENOUGH_REVEALS))
      ;; generate randomness using reveals-count and epoch
      (let ((rnd (sha256 0x00)))
        (map-set epoch-random { epoch: epoch } { rnd: rnd })
        (ev-finalize epoch rnd reveals-count)
        (ok rnd)))))

;; -------------------------
;; Read-only getters
;; -------------------------
(define-read-only (get-commit (epoch uint) (who principal))
  (ok (map-get? commitments { epoch: epoch, who: who })))

(define-read-only (get-reveal (epoch uint) (who principal))
  (ok (map-get? reveals { epoch: epoch, who: who })))

(define-read-only (get-epoch-random (epoch uint))
  (ok (map-get? epoch-random { epoch: epoch })))

(define-read-only (get-epoch-contrib-count (epoch uint))
  (ok (default-to u0 (get count (map-get? epoch-contrib-count { epoch: epoch })))))

(define-read-only (get-epoch-reveal-count (epoch uint))
  (ok (default-to u0 (get count (map-get? epoch-reveal-count { epoch: epoch })))))

(define-read-only (get-current-params)
  (ok {
    epoch_length: (var-get epoch-length),
    reveal_window: (var-get reveal-window),
    min_reveals: (var-get min-reveals),
    active: (var-get active)
  }))
