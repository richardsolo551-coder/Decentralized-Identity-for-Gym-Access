import { describe, it, expect, beforeEach } from "vitest";
import { stringUtf8CV, uintCV, bufferCV } from "@stacks/transactions";

const ERR_INVALID_DID = 100;
const ERR_NOT_AUTHORIZED = 101;
const ERR_DID_ALREADY_EXISTS = 102;
const ERR_DID_NOT_FOUND = 103;
const ERR_INVALID_PUB_KEY = 104;
const ERR_INVALID_METADATA = 105;
const ERR_MAX_DIDS_EXCEEDED = 106;
const ERR_INVALID_AUTHORITY = 107;
const ERR_INVALID_TIMESTAMP = 108;

interface Identity {
  pubKey: Buffer;
  creator: string;
  timestamp: number;
  metadata: string;
  active: boolean;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class IdentityRegistryMock {
  state: {
    nextDidId: number;
    maxDids: number;
    authorityContract: string | null;
    identities: Map<string, Identity>;
    didToId: Map<string, number>;
  } = {
    nextDidId: 0,
    maxDids: 10000,
    authorityContract: null,
    identities: new Map(),
    didToId: new Map(),
  };
  blockHeight: number = 100;
  caller: string = "ST1TEST";
  authorities: Set<string> = new Set(["ST1TEST"]);

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextDidId: 0,
      maxDids: 10000,
      authorityContract: null,
      identities: new Map(),
      didToId: new Map(),
    };
    this.blockHeight = 100;
    this.caller = "ST1TEST";
    this.authorities = new Set(["ST1TEST"]);
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (contractPrincipal === "SP000000000000000000002Q6VF78") return { ok: false, value: ERR_INVALID_AUTHORITY };
    if (this.state.authorityContract !== null) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  registerIdentity(did: string, pubKey: Buffer, metadata: string): Result<number> {
    if (this.state.nextDidId >= this.state.maxDids) return { ok: false, value: ERR_MAX_DIDS_EXCEEDED };
    if (did.length < 8 || did.length > 64) return { ok: false, value: ERR_INVALID_DID };
    if (pubKey.length !== 33) return { ok: false, value: ERR_INVALID_PUB_KEY };
    if (metadata.length > 256) return { ok: false, value: ERR_INVALID_METADATA };
    if (this.state.didToId.has(did)) return { ok: false, value: ERR_DID_ALREADY_EXISTS };
    const id = this.state.nextDidId;
    this.state.identities.set(did, { pubKey, creator: this.caller, timestamp: this.blockHeight, metadata, active: true });
    this.state.didToId.set(did, id);
    this.state.nextDidId++;
    return { ok: true, value: id };
  }

  updateIdentityMetadata(did: string, newMetadata: string): Result<boolean> {
    const identity = this.state.identities.get(did);
    if (!identity) return { ok: false, value: ERR_DID_NOT_FOUND };
    if (identity.creator !== this.caller) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newMetadata.length > 256) return { ok: false, value: ERR_INVALID_METADATA };
    this.state.identities.set(did, { ...identity, metadata: newMetadata, timestamp: this.blockHeight });
    return { ok: true, value: true };
  }

  deactivateIdentity(did: string): Result<boolean> {
    const identity = this.state.identities.get(did);
    if (!identity) return { ok: false, value: ERR_DID_NOT_FOUND };
    if (!this.state.authorityContract && identity.creator !== this.caller) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.identities.set(did, { ...identity, active: false });
    return { ok: true, value: true };
  }

  reactivateIdentity(did: string): Result<boolean> {
    const identity = this.state.identities.get(did);
    if (!identity) return { ok: false, value: ERR_DID_NOT_FOUND };
    if (identity.creator !== this.caller) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.identities.set(did, { ...identity, active: true, timestamp: this.blockHeight });
    return { ok: true, value: true };
  }

  getIdentity(did: string): Identity | null {
    return this.state.identities.get(did) || null;
  }

  getDidId(did: string): number | null {
    return this.state.didToId.get(did) || null;
  }

  getDidCount(): Result<number> {
    return { ok: true, value: this.state.nextDidId };
  }
}

describe("IdentityRegistry", () => {
  let contract: IdentityRegistryMock;

  beforeEach(() => {
    contract = new IdentityRegistryMock();
    contract.reset();
  });

  it("sets authority contract successfully", () => {
    const result = contract.setAuthorityContract("ST2TEST");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.authorityContract).toBe("ST2TEST");
  });

  it("rejects duplicate DID", () => {
    const pubKey = Buffer.alloc(33, 1);
    contract.registerIdentity("did:example:123", pubKey, "User metadata");
    const result = contract.registerIdentity("did:example:123", pubKey, "New metadata");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_DID_ALREADY_EXISTS);
  });

  it("updates metadata successfully", () => {
    const pubKey = Buffer.alloc(33, 1);
    contract.registerIdentity("did:example:123", pubKey, "Old metadata");
    const result = contract.updateIdentityMetadata("did:example:123", "New metadata");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const identity = contract.getIdentity("did:example:123");
    expect(identity?.metadata).toBe("New metadata");
    expect(identity?.timestamp).toBe(100);
  });

  it("deactivates identity successfully", () => {
    const pubKey = Buffer.alloc(33, 1);
    contract.registerIdentity("did:example:123", pubKey, "User metadata");
    const result = contract.deactivateIdentity("did:example:123");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const identity = contract.getIdentity("did:example:123");
    expect(identity?.active).toBe(false);
  });

  it("reactivates identity successfully", () => {
    const pubKey = Buffer.alloc(33, 1);
    contract.registerIdentity("did:example:123", pubKey, "User metadata");
    contract.deactivateIdentity("did:example:123");
    const result = contract.reactivateIdentity("did:example:123");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const identity = contract.getIdentity("did:example:123");
    expect(identity?.active).toBe(true);
    expect(identity?.timestamp).toBe(100);
  });

  it("rejects unauthorized metadata update", () => {
    const pubKey = Buffer.alloc(33, 1);
    contract.registerIdentity("did:example:123", pubKey, "User metadata");
    contract.caller = "ST2FAKE";
    const result = contract.updateIdentityMetadata("did:example:123", "New metadata");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("rejects invalid DID length", () => {
    const pubKey = Buffer.alloc(33, 1);
    const result = contract.registerIdentity("short", pubKey, "User metadata");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_DID);
  });

  it("rejects invalid public key", () => {
    const pubKey = Buffer.alloc(32, 1);
    const result = contract.registerIdentity("did:example:123", pubKey, "User metadata");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_PUB_KEY);
  });

  it("rejects max DIDs exceeded", () => {
    contract.state.maxDids = 0;
    const pubKey = Buffer.alloc(33, 1);
    const result = contract.registerIdentity("did:example:123", pubKey, "User metadata");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_DIDS_EXCEEDED);
  });

  it("returns correct DID count", () => {
    const pubKey = Buffer.alloc(33, 1);
    contract.registerIdentity("did:example:123", pubKey, "User metadata");
    contract.registerIdentity("did:example:456", pubKey, "Other metadata");
    const result = contract.getDidCount();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });
});