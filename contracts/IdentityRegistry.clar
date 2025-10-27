(define-constant ERR-INVALID-DID u100)
(define-constant ERR-NOT-AUTHORIZED u101)
(define-constant ERR-DID-ALREADY-EXISTS u102)
(define-constant ERR-DID-NOT-FOUND u103)
(define-constant ERR-INVALID-PUB-KEY u104)
(define-constant ERR-INVALID-METADATA u105)
(define-constant ERR-MAX-DIDS-EXCEEDED u106)
(define-constant ERR-INVALID-AUTHORITY u107)
(define-constant ERR-INVALID-TIMESTAMP u108)

(define-data-var next-did-id uint u0)
(define-data-var max-dids uint u10000)
(define-data-var authority-contract (optional principal) none)

(define-map identities
  { did: (string-utf8 64) }
  { pub-key: (buff 33), creator: principal, timestamp: uint, metadata: (string-utf8 256), active: bool }
)

(define-map did-to-id
  { did: (string-utf8 64) }
  uint
)

(define-read-only (get-identity (did (string-utf8 64)))
  (map-get? identities { did: did })
)

(define-read-only (get-did-id (did (string-utf8 64)))
  (map-get? did-to-id { did: did })
)

(define-read-only (get-did-count)
  (ok (var-get next-did-id))
)

(define-private (validate-did (did (string-utf8 64)))
  (if (and (> (len did) u8) (<= (len did) u64))
      (ok true)
      (err ERR-INVALID-DID))
)

(define-private (validate-pub-key (pub-key (buff 33)))
  (if (is-eq (len pub-key) u33)
      (ok true)
      (err ERR-INVALID-PUB-KEY))
)

(define-private (validate-metadata (meta (string-utf8 256)))
  (if (<= (len meta) u256)
      (ok true)
      (err ERR-INVALID-METADATA))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
      (ok true)
      (err ERR-INVALID-TIMESTAMP))
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

(define-public (register-identity (did (string-utf8 64)) (pub-key (buff 33)) (metadata (string-utf8 256)))
  (let (
        (next-id (var-get next-did-id))
        (did-exists (map-get? did-to-id { did: did }))
      )
    (asserts! (< next-id (var-get max-dids)) (err ERR-MAX-DIDS-EXCEEDED))
    (try! (validate-did did))
    (try! (validate-pub-key pub-key))
    (try! (validate-metadata metadata))
    (asserts! (is-none did-exists) (err ERR-DID-ALREADY-EXISTS))
    (map-set identities
      { did: did }
      { pub-key: pub-key, creator: tx-sender, timestamp: block-height, metadata: metadata, active: true }
    )
    (map-set did-to-id { did: did } next-id)
    (var-set next-did-id (+ next-id u1))
    (ok next-id)
  )
)

(define-public (update-identity-metadata (did (string-utf8 64)) (new-metadata (string-utf8 256)))
  (let (
        (identity-opt (map-get? identities { did: did }))
      )
    (match identity-opt
      identity
        (begin
          (asserts! (is-eq (get creator identity) tx-sender) (err ERR-NOT-AUTHORIZED))
          (try! (validate-metadata new-metadata))
          (try! (validate-timestamp block-height))
          (map-set identities
            { did: did }
            { pub-key: (get pub-key identity), creator: (get creator identity), timestamp: block-height, metadata: new-metadata, active: (get active identity) }
          )
          (ok true)
        )
      (err ERR-DID-NOT-FOUND)
    )
  )
)

(define-public (deactivate-identity (did (string-utf8 64)))
  (let (
        (identity-opt (map-get? identities { did: did }))
      )
    (match identity-opt
      identity
        (begin
          (asserts! (or (is-eq (get creator identity) tx-sender) (is-some (var-get authority-contract))) (err ERR-NOT-AUTHORIZED))
          (map-set identities
            { did: did }
            { pub-key: (get pub-key identity), creator: (get creator identity), timestamp: (get timestamp identity), metadata: (get metadata identity), active: false }
          )
          (ok true)
        )
      (err ERR-DID-NOT-FOUND)
    )
  )
)

(define-public (reactivate-identity (did (string-utf8 64)))
  (let (
        (identity-opt (map-get? identities { did: did }))
      )
    (match identity-opt
      identity
        (begin
          (asserts! (is-eq (get creator identity) tx-sender) (err ERR-NOT-AUTHORIZED))
          (map-set identities
            { did: did }
            { pub-key: (get pub-key identity), creator: (get creator identity), timestamp: block-height, metadata: (get metadata identity), active: true }
          )
          (ok true)
        )
      (err ERR-DID-NOT-FOUND)
    )
  )
)