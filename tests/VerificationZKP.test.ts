import { describe, it, expect, beforeEach } from "vitest";
import { stringUtf8CV, uintCV, bufferCV } from "@stacks/transactions";

const ERR_INVALID_PROOF = 100;
const ERR_INVALID_CREDENTIAL = 101;
const ERR_NOT_AUTHORIZED = 102;
const ERR_MEMBERSHIP_NOT_FOUND = 103;
const ERR_EXPIRED_MEMBERSHIP = 104;
const ERR_INVALID_GYM = 105;
const ERR_PROOF_MISMATCH = 106;
const ERR_INVALID_SALT = 107;
const ERR_UNVERIFIED_DID = 108;
const ERR_INVALID_ZKP_PARAMS = 109;
const ERR_MAX_PROOFS_EXCEEDED = 110;

interface Credential {
  hash: Buffer;
  expiry: number;
  status: boolean;
}

interface Proof {
  proofHash: Buffer;
  didCommitment: Buffer;
  verifier: string;
  timestamp: number;
}

interface GymRegistration {
  publicKey: Buffer;
  name: string;
  verified: boolean;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class VerificationZKPMock {
  state: {
    nextProofId: number;
    maxProofs: number;
    authorityContract: string | null;
    credentials: Map<string, Credential>;
    proofs: Map<number, Proof>;
    gymRegistrations: Map<number, GymRegistration>;
  } = {
    nextProofId: 0,
    maxProofs: 10000,
    authorityContract: null,
    credentials: new Map(),
    proofs: new Map(),
    gymRegistrations: new Map(),
  };
  blockHeight: number = 100;
  caller: string = "ST1TEST";
  authorities: Set<string> = new Set(["ST1TEST"]);

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextProofId: 0,
      maxProofs: 10000,
      authorityContract: null,
      credentials: new Map(),
      proofs: new Map(),
      gymRegistrations: new Map(),
    };
    this.blockHeight = 100;
    this.caller = "ST1TEST";
    this.authorities = new Set(["ST1TEST"]);
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (this.state.authorityContract !== null) return { ok: false, value: false };
    if (contractPrincipal === "SP000000000000000000002Q6VF78") return { ok: false, value: false };
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  registerGym(gymId: number, pubKey: Buffer, name: string): Result<boolean> {
    if (gymId <= 0) return { ok: false, value: ERR_INVALID_GYM };
    if (pubKey.length !== 33) return { ok: false, value: ERR_INVALID_ZKP_PARAMS };
    if (name.length === 0 || name.length > 50) return { ok: false, value: ERR_INVALID_GYM };
    if (!this.state.authorityContract) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.gymRegistrations.set(gymId, { publicKey: pubKey, name, verified: true });
    return { ok: true, value: true };
  }

  commitCredential(did: string, gymId: number, salt: Buffer, expiry: number): Result<Buffer> {
    if (did.length < 8 || did.length > 64) return { ok: false, value: ERR_UNVERIFIED_DID };
    if (gymId <= 0) return { ok: false, value: ERR_INVALID_GYM };
    if (salt.length !== 16) return { ok: false, value: ERR_INVALID_SALT };
    if (expiry <= this.blockHeight) return { ok: false, value: ERR_EXPIRED_MEMBERSHIP };
    if (!this.isGymVerified(gymId)) return { ok: false, value: ERR_INVALID_GYM };
    const key = `${did}-${gymId}`;
    const commit = Buffer.from(require('crypto').createHash('sha256').update(Buffer.concat([Buffer.from(did), salt])).digest());
    this.state.credentials.set(key, { hash: commit, expiry, status: true });
    return { ok: true, value: commit };
  }

  generateProof(did: string, gymId: number, params: Buffer): Result<number> {
    if (this.state.nextProofId >= this.state.maxProofs) return { ok: false, value: ERR_MAX_PROOFS_EXCEEDED };
    if (did.length < 8 || did.length > 64) return { ok: false, value: ERR_UNVERIFIED_DID };
    if (gymId <= 0) return { ok: false, value: ERR_INVALID_GYM };
    if (params.length !== 64) return { ok: false, value: ERR_INVALID_ZKP_PARAMS };
    const key = `${did}-${gymId}`;
    const cred = this.state.credentials.get(key);
    if (!cred) return { ok: false, value: ERR_MEMBERSHIP_NOT_FOUND };
    if (cred.expiry <= this.blockHeight) return { ok: false, value: ERR_EXPIRED_MEMBERSHIP };
    const proofHash = Buffer.from(require('crypto').createHash('sha256').update(params).digest());
    const id = this.state.nextProofId;
    this.state.proofs.set(id, { proofHash, didCommitment: cred.hash, verifier: this.caller, timestamp: this.blockHeight });
    this.state.nextProofId++;
    return { ok: true, value: id };
  }

  verifyCredential(proofId: number, did: string, gymId: number, salt: Buffer, params: Buffer): Result<{ verified: boolean; gymName: string }> {
    const proof = this.state.proofs.get(proofId);
    if (!proof) return { ok: false, value: ERR_INVALID_PROOF };
    const key = `${did}-${gymId}`;
    const cred = this.state.credentials.get(key);
    if (!cred) return { ok: false, value: ERR_MEMBERSHIP_NOT_FOUND };
    if (did.length < 8 || did.length > 64) return { ok: false, value: ERR_UNVERIFIED_DID };
    if (gymId <= 0) return { ok: false, value: ERR_INVALID_GYM };
    if (salt.length !== 16) return { ok: false, value: ERR_INVALID_SALT };
    if (params.length !== 64) return { ok: false, value: ERR_INVALID_ZKP_PARAMS };
    if (cred.expiry <= this.blockHeight) return { ok: false, value: ERR_EXPIRED_MEMBERSHIP };
    const commit = Buffer.from(require('crypto').createHash('sha256').update(Buffer.concat([Buffer.from(did), salt])).digest());
    const computed = Buffer.from(require('crypto').createHash('sha256').update(Buffer.concat([proof.proofHash, params])).digest());
    if (!commit.equals(proof.didCommitment)) return { ok: false, value: ERR_PROOF_MISMATCH };
    if (!computed.equals(commit)) return { ok: false, value: ERR_PROOF_MISMATCH };
    const gym = this.state.gymRegistrations.get(gymId);
    if (!gym) return { ok: false, value: ERR_INVALID_GYM };
    return { ok: true, value: { verified: true, gymName: gym.name } };
  }

  revokeCredential(did: string, gymId: number): Result<boolean> {
    const key = `${did}-${gymId}`;
    const cred = this.state.credentials.get(key);
    if (!cred) return { ok: false, value: ERR_MEMBERSHIP_NOT_FOUND };
    if (!this.state.authorityContract && this.caller !== cred.hash.toString('hex')) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.credentials.set(key, { ...cred, status: false });
    return { ok: true, value: true };
  }

  isGymVerified(gymId: number): boolean {
    const gym = this.state.gymRegistrations.get(gymId);
    return gym ? gym.verified : false;
  }

  getCredential(did: string, gymId: number): Credential | null {
    const key = `${did}-${gymId}`;
    return this.state.credentials.get(key) || null;
  }

  getProof(id: number): Proof | null {
    return this.state.proofs.get(id) || null;
  }
}

describe("VerificationZKP", () => {
  let contract: VerificationZKPMock;

  beforeEach(() => {
    contract = new VerificationZKPMock();
    contract.reset();
  });

  it("sets authority contract successfully", () => {
    const result = contract.setAuthorityContract("ST2TEST");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.authorityContract).toBe("ST2TEST");
  });

  it("registers gym successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const pubKey = Buffer.alloc(33, 1);
    const result = contract.registerGym(1, pubKey, "GymA");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const gym = contract.state.gymRegistrations.get(1);
    expect(gym?.name).toBe("GymA");
    expect(gym?.verified).toBe(true);
  });

  it("commits credential successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.registerGym(1, Buffer.alloc(33, 1), "GymA");
    const salt = Buffer.alloc(16, 2);
    const result = contract.commitCredential("did:example:123", 1, salt, 200);
    expect(result.ok).toBe(true);
    expect(result.value.length).toBe(32);
    const cred = contract.getCredential("did:example:123", 1);
    expect(cred?.status).toBe(true);
    expect(cred?.expiry).toBe(200);
  });

  it("generates proof successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.registerGym(1, Buffer.alloc(33, 1), "GymA");
    const salt = Buffer.alloc(16, 2);
    contract.commitCredential("did:example:123", 1, salt, 200);
    const params = Buffer.alloc(64, 3);
    const result = contract.generateProof("did:example:123", 1, params);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);
    const proof = contract.getProof(0);
    expect(proof?.verifier).toBe("ST1TEST");
    expect(proof?.timestamp).toBe(100);
  });

  it("revokes credential successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.registerGym(1, Buffer.alloc(33, 1), "GymA");
    const salt = Buffer.alloc(16, 2);
    contract.commitCredential("did:example:123", 1, salt, 200);
    const result = contract.revokeCredential("did:example:123", 1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const cred = contract.getCredential("did:example:123", 1);
    expect(cred?.status).toBe(false);
  });

  it("rejects verification with invalid proof", () => {
    const result = contract.verifyCredential(999, "did:example:123", 1, Buffer.alloc(16), Buffer.alloc(64));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_PROOF);
  });

  it("rejects commit with unverified gym", () => {
    const salt = Buffer.alloc(16, 2);
    const result = contract.commitCredential("did:example:123", 1, salt, 200);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_GYM);
  });

  it("rejects invalid DID length", () => {
    const salt = Buffer.alloc(16, 2);
    const result = contract.commitCredential("short", 1, salt, 200);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_UNVERIFIED_DID);
  });

  it("rejects max proofs exceeded", () => {
    contract.state.maxProofs = 0;
    const params = Buffer.alloc(64, 3);
    const result = contract.generateProof("did:example:123", 1, params);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_PROOFS_EXCEEDED);
  });
});