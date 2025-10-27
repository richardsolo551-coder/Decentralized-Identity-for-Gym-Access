(define-constant ERR-INVALID-PROOF u100)
(define-constant ERR-INVALID-CREDENTIAL u101)
(define-constant ERR-NOT-AUTHORIZED u102)
(define-constant ERR-MEMBERSHIP-NOT-FOUND u103)
(define-constant ERR-EXPIRED-MEMBERSHIP u104)
(define-constant ERR-INVALID-GYM u105)
(define-constant ERR-PROOF-MISMATCH u106)
(define-constant ERR-INVALID-SALT u107)
(define-constant ERR-UNVERIFIED-DID u108)
(define-constant ERR-INVALID-ZKP-PARAMS u109)
(define-constant ERR-MAX-PROOFS-EXCEEDED u110)

(define-data-var next-proof-id uint u0)
(define-data-var max-proofs uint u10000)
(define-data-var authority-contract (optional principal) none)

(define-map credentials
  { did: (string-utf8 64), gym-id: uint }
  { hash: (buff 32), expiry: uint, status: bool }
)

(define-map proofs
  uint
  { proof-hash: (buff 32), did-commitment: (buff 32), verifier: principal, timestamp: uint }
)

(define-map gym-registrations
  uint
  { public-key: (buff 33), name: (string-utf8 50), verified: bool }
)

(define-read-only (get-credential (did (string-utf8 64)) (gym-id uint))
  (map-get? credentials { did: did, gym-id: gym-id })
)

(define-read-only (get-proof (id uint))
  (map-get? proofs id)
)

(define-read-only (is-gym-verified (gym-id uint))
  (match (map-get? gym-registrations gym-id)
    reg (get verified reg)
    false
  )
)

(define-private (validate-did (did (string-utf8 64)))
  (if (and (> (len did) u8) (<= (len did) u64))
      (ok true)
      (err ERR-UNVERIFIED-DID))
)

(define-private (validate-gym-id (gym-id uint))
  (if (> gym-id u0)
      (ok true)
      (err ERR-INVALID-GYM))
)

(define-private (validate-expiry (expiry uint))
  (if (> expiry block-height)
      (ok true)
      (err ERR-EXPIRED-MEMBERSHIP))
)

(define-private (validate-proof-hash (ph (buff 32)))
  (if (is-eq (len ph) u32)
      (ok true)
      (err ERR-INVALID-PROOF))
)

(define-private (validate-commitment (commit (buff 32)))
  (if (is-eq (len commit) u32)
      (ok true)
      (err ERR-INVALID-CREDENTIAL))
)

(define-private (validate-salt (salt (buff 16)))
  (if (is-eq (len salt) u16)
      (ok true)
      (err ERR-INVALID-SALT))
)

(define-private (validate-zkp-params (params (buff 64)))
  (if (is-eq (len params) u64)
      (ok true)
      (err ERR-INVALID-ZKP-PARAMS))
)

(define-private (hash-commitment (did (string-utf8 64)) (salt (buff 16)))
  (sha256 (concat (as-max-len? (some (string-ascii did)) u64) salt))
)

(define-private (verify-zkp-simple (proof-hash (buff 32)) (expected-commit (buff 32)) (params (buff 64)))
  (let ((computed (sha256 (concat proof-hash params))))
    (if (is-eq computed expected-commit)
        (ok true)
        (err ERR-PROOF-MISMATCH))
  )
)

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (asserts! (is-none (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (asserts! (not (is-eq contract-principal 'SP000000000000000000002Q6VF78)) (err ERR-NOT-AUTHORIZED))
    (var-set authority-contract (some contract-principal))
    (ok true)
  )
)

(define-public (register-gym (gym-id uint) (pub-key (buff 33)) (name (string-utf8 50)))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-NOT-AUTHORIZED))
    (try! (validate-gym-id gym-id))
    (asserts! (is-eq (len pub-key) u33) (err ERR-INVALID-ZKP-PARAMS))
    (asserts! (and (> (len name) u0) (<= (len name) u50)) (err ERR-INVALID-GYM))
    (map-set gym-registrations gym-id { public-key: pub-key, name: name, verified: true })
    (ok true)
  )
)

(define-public (commit-credential (did (string-utf8 64)) (gym-id uint) (salt (buff 16)) (expiry uint))
  (let (
        (commit (try! (hash-commitment did salt)))
        (cred { hash: commit, expiry: expiry, status: true })
      )
    (try! (validate-did did))
    (try! (validate-gym-id gym-id))
    (try! (validate-salt salt))
    (try! (validate-expiry expiry))
    (asserts! (is-gym-verified gym-id) (err ERR-INVALID-GYM))
    (map-set credentials { did: did, gym-id: gym-id } cred)
    (ok commit)
  )
)

(define-public (generate-proof (did (string-utf8 64)) (gym-id uint) (params (buff 64)))
  (let (
        (next-id (var-get next-proof-id))
        (cred-opt (get-credential did gym-id))
      )
    (asserts! (< next-id (var-get max-proofs)) (err ERR-MAX-PROOFS-EXCEEDED))
    (match cred-opt
      cred
        (begin
          (try! (validate-did did))
          (try! (validate-gym-id gym-id))
          (try! (validate-zkp-params params))
          (try! (validate-expiry (get expiry cred)))
          (let (
                (proof-hash (sha256 params))
                (proof { proof-hash: proof-hash, did-commitment: (get hash cred), verifier: tx-sender, timestamp: block-height })
              )
            (map-set proofs next-id proof)
            (var-set next-proof-id (+ next-id u1))
            (ok next-id)
          )
        )
      (err ERR-MEMBERSHIP-NOT-FOUND)
    )
  )
)

(define-public (verify-credential (proof-id uint) (did (string-utf8 64)) (gym-id uint) (salt (buff 16)) (params (buff 64)))
  (let (
        (proof-opt (get-proof proof-id))
        (cred-opt (get-credential did gym-id))
      )
    (match proof-opt
      proof
        (match cred-opt
          cred
            (begin
              (try! (validate-did did))
              (try! (validate-gym-id gym-id))
              (try! (validate-salt salt))
              (try! (validate-zkp-params params))
              (try! (validate-expiry (get expiry cred)))
              (let (
                    (commit (try! (hash-commitment did salt)))
                    (zkp-result (try! (verify-zkp-simple (get proof-hash proof) commit params)))
                  )
                (asserts! (is-eq commit (get did-commitment proof)) (err ERR-PROOF-MISMATCH))
                (ok { verified: true, gym-name: (get name (unwrap! (map-get? gym-registrations gym-id) (err ERR-INVALID-GYM))) })
              )
            )
          none
            (err ERR-MEMBERSHIP-NOT-FOUND)
        )
      none
        (err ERR-INVALID-PROOF)
    )
  )
)

(define-public (revoke-credential (did (string-utf8 64)) (gym-id uint))
  (let ((cred-opt (get-credential did gym-id)))
    (match cred-opt
      cred
        (begin
          (asserts! (or (is-eq tx-sender (get creator cred)) (is-some (var-get authority-contract))) (err ERR-NOT-AUTHORIZED))
          (map-set credentials { did: did, gym-id: gym-id } { hash: (get hash cred), expiry: (get expiry cred), status: false })
          (ok true)
        )
      none
        (err ERR-MEMBERSHIP-NOT-FOUND)
    )
  )
)