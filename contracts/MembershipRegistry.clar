(define-constant ERR-INVALID-DID u100)
(define-constant ERR-INVALID-GYM-ID u101)
(define-constant ERR-NOT-AUTHORIZED u102)
(define-constant ERR-MEMBERSHIP-EXISTS u103)
(define-constant ERR-MEMBERSHIP-NOT-FOUND u104)
(define-constant ERR-INVALID-PLAN u105)
(define-constant ERR-INVALID-START-TIME u106)
(define-constant ERR-INVALID-DURATION u107)
(define-constant ERR-MAX-MEMBERSHIPS-EXCEEDED u108)
(define-constant ERR-INVALID-AUTHORITY u109)

(define-data-var next-membership-id uint u0)
(define-data-var max-memberships uint u10000)
(define-data-var authority-contract (optional principal) none)

(define-map memberships
  { did: (string-utf8 64), gym-id: uint }
  { plan: (string-utf8 20), start-time: uint, duration: uint, active: bool, creator: principal }
)

(define-map membership-ids
  { did: (string-utf8 64), gym-id: uint }
  uint
)

(define-read-only (get-membership (did (string-utf8 64)) (gym-id uint))
  (map-get? memberships { did: did, gym-id: gym-id })
)

(define-read-only (get-membership-id (did (string-utf8 64)) (gym-id uint))
  (map-get? membership-ids { did: did, gym-id: gym-id })
)

(define-read-only (get-membership-count)
  (ok (var-get next-membership-id))
)

(define-private (validate-did (did (string-utf8 64)))
  (if (and (> (len did) u8) (<= (len did) u64))
      (ok true)
      (err ERR-INVALID-DID))
)

(define-private (validate-gym-id (gym-id uint))
  (if (> gym-id u0)
      (ok true)
      (err ERR-INVALID-GYM-ID))
)

(define-private (validate-plan (plan (string-utf8 20)))
  (if (or (is-eq plan "monthly") (is-eq plan "yearly") (is-eq plan "weekly"))
      (ok true)
      (err ERR-INVALID-PLAN))
)

(define-private (validate-start-time (start uint))
  (if (>= start block-height)
      (ok true)
      (err ERR-INVALID-START-TIME))
)

(define-private (validate-duration (duration uint))
  (if (> duration u0)
      (ok true)
      (err ERR-INVALID-DURATION))
)

(define-private (validate-authority (principal-id principal))
  (if (not (is-eq principal-id 'SP000000000000000000002Q6VF78))
      (ok true)
      (err ERR-INVALID-AUTHORITY))
)

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (try! (validate-authority contract-principal))
    (asserts! (is-none (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (var-set authority-contract (some contract-principal))
    (ok true)
  )
)

(define-public (register-membership (did (string-utf8 64)) (gym-id uint) (plan (string-utf8 20)) (start-time uint) (duration uint))
  (let (
        (next-id (var-get next-membership-id))
        (membership-exists (map-get? membership-ids { did: did, gym-id: gym-id }))
      )
    (asserts! (< next-id (var-get max-memberships)) (err ERR-MAX-MEMBERSHIPS-EXCEEDED))
    (try! (validate-did did))
    (try! (validate-gym-id gym-id))
    (try! (validate-plan plan))
    (try! (validate-start-time start-time))
    (try! (validate-duration duration))
    (asserts! (is-none membership-exists) (err ERR-MEMBERSHIP-EXISTS))
    (map-set memberships
      { did: did, gym-id: gym-id }
      { plan: plan, start-time: start-time, duration: duration, active: true, creator: tx-sender }
    )
    (map-set membership-ids { did: did, gym-id: gym-id } next-id)
    (var-set next-membership-id (+ next-id u1))
    (ok next-id)
  )
)

(define-public (update-membership-plan (did (string-utf8 64)) (gym-id uint) (new-plan (string-utf8 20)))
  (let (
        (membership-opt (map-get? memberships { did: did, gym-id: gym-id }))
      )
    (match membership-opt
      membership
        (begin
          (asserts! (is-eq (get creator membership) tx-sender) (err ERR-NOT-AUTHORIZED))
          (try! (validate-plan new-plan))
          (map-set memberships
            { did: did, gym-id: gym-id }
            { plan: new-plan, start-time: (get start-time membership), duration: (get duration membership), active: (get active membership), creator: (get creator membership) }
          )
          (ok true)
        )
      (err ERR-MEMBERSHIP-NOT-FOUND)
    )
  )
)

(define-public (deactivate-membership (did (string-utf8 64)) (gym-id uint))
  (let (
        (membership-opt (map-get? memberships { did: did, gym-id: gym-id }))
      )
    (match membership-opt
      membership
        (begin
          (asserts! (or (is-eq (get creator membership) tx-sender) (is-some (var-get authority-contract))) (err ERR-NOT-AUTHORIZED))
          (map-set memberships
            { did: did, gym-id: gym-id }
            { plan: (get plan membership), start-time: (get start-time membership), duration: (get duration membership), active: false, creator: (get creator membership) }
          )
          (ok true)
        )
      (err ERR-MEMBERSHIP-NOT-FOUND)
    )
  )
)