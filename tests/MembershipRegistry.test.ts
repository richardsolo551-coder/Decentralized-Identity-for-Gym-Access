import { describe, it, expect, beforeEach } from "vitest";
import { stringUtf8CV, uintCV } from "@stacks/transactions";

const ERR_INVALID_DID = 100;
const ERR_INVALID_GYM_ID = 101;
const ERR_NOT_AUTHORIZED = 102;
const ERR_MEMBERSHIP_EXISTS = 103;
const ERR_MEMBERSHIP_NOT_FOUND = 104;
const ERR_INVALID_PLAN = 105;
const ERR_INVALID_START_TIME = 106;
const ERR_INVALID_DURATION = 107;
const ERR_MAX_MEMBERSHIPS_EXCEEDED = 108;
const ERR_INVALID_AUTHORITY = 109;

interface Membership {
  plan: string;
  startTime: number;
  duration: number;
  active: boolean;
  creator: string;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class MembershipRegistryMock {
  state: {
    nextMembershipId: number;
    maxMemberships: number;
    authorityContract: string | null;
    memberships: Map<string, Membership>;
    membershipIds: Map<string, number>;
  } = {
    nextMembershipId: 0,
    maxMemberships: 10000,
    authorityContract: null,
    memberships: new Map(),
    membershipIds: new Map(),
  };
  blockHeight: number = 100;
  caller: string = "ST1TEST";
  authorities: Set<string> = new Set(["ST1TEST"]);

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextMembershipId: 0,
      maxMemberships: 10000,
      authorityContract: null,
      memberships: new Map(),
      membershipIds: new Map(),
    };
    this.blockHeight = 100;
    this.caller = "ST1TEST";
    this.authorities = new Set(["ST1TEST"]);
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (contractPrincipal === "SP000000000000000000002Q6VF78")
      return { ok: false, value: ERR_INVALID_AUTHORITY };
    if (this.state.authorityContract !== null)
      return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  registerMembership(
    did: string,
    gymId: number,
    plan: string,
    startTime: number,
    duration: number
  ): Result<number> {
    if (this.state.nextMembershipId >= this.state.maxMemberships)
      return { ok: false, value: ERR_MAX_MEMBERSHIPS_EXCEEDED };
    if (did.length < 8 || did.length > 64)
      return { ok: false, value: ERR_INVALID_DID };
    if (gymId <= 0) return { ok: false, value: ERR_INVALID_GYM_ID };
    if (!["monthly", "yearly", "weekly"].includes(plan))
      return { ok: false, value: ERR_INVALID_PLAN };
    if (startTime < this.blockHeight)
      return { ok: false, value: ERR_INVALID_START_TIME };
    if (duration <= 0) return { ok: false, value: ERR_INVALID_DURATION };
    const key = `${did}-${gymId}`;
    if (this.state.membershipIds.has(key))
      return { ok: false, value: ERR_MEMBERSHIP_EXISTS };
    const id = this.state.nextMembershipId;
    this.state.memberships.set(key, {
      plan,
      startTime,
      duration,
      active: true,
      creator: this.caller,
    });
    this.state.membershipIds.set(key, id);
    this.state.nextMembershipId++;
    return { ok: true, value: id };
  }

  updateMembershipPlan(
    did: string,
    gymId: number,
    newPlan: string
  ): Result<boolean> {
    const key = `${did}-${gymId}`;
    const membership = this.state.memberships.get(key);
    if (!membership) return { ok: false, value: ERR_MEMBERSHIP_NOT_FOUND };
    if (membership.creator !== this.caller)
      return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (!["monthly", "yearly", "weekly"].includes(newPlan))
      return { ok: false, value: ERR_INVALID_PLAN };
    this.state.memberships.set(key, { ...membership, plan: newPlan });
    return { ok: true, value: true };
  }

  deactivateMembership(did: string, gymId: number): Result<boolean> {
    const key = `${did}-${gymId}`;
    const membership = this.state.memberships.get(key);
    if (!membership) return { ok: false, value: ERR_MEMBERSHIP_NOT_FOUND };
    if (!this.state.authorityContract && membership.creator !== this.caller)
      return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.memberships.set(key, { ...membership, active: false });
    return { ok: true, value: true };
  }

  getMembership(did: string, gymId: number): Membership | null {
    const key = `${did}-${gymId}`;
    return this.state.memberships.get(key) || null;
  }

  getMembershipId(did: string, gymId: number): number | null {
    const key = `${did}-${gymId}`;
    return this.state.membershipIds.get(key) || null;
  }

  getMembershipCount(): Result<number> {
    return { ok: true, value: this.state.nextMembershipId };
  }
}

describe("MembershipRegistry", () => {
  let contract: MembershipRegistryMock;

  beforeEach(() => {
    contract = new MembershipRegistryMock();
    contract.reset();
  });

  it("sets authority contract successfully", () => {
    const result = contract.setAuthorityContract("ST2TEST");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.authorityContract).toBe("ST2TEST");
  });

  it("rejects duplicate membership", () => {
    contract.registerMembership("did:example:123", 1, "monthly", 100, 30);
    const result = contract.registerMembership(
      "did:example:123",
      1,
      "yearly",
      100,
      365
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MEMBERSHIP_EXISTS);
  });

  it("updates membership plan successfully", () => {
    contract.registerMembership("did:example:123", 1, "monthly", 100, 30);
    const result = contract.updateMembershipPlan(
      "did:example:123",
      1,
      "yearly"
    );
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const membership = contract.getMembership("did:example:123", 1);
    expect(membership?.plan).toBe("yearly");
  });

  it("deactivates membership successfully", () => {
    contract.registerMembership("did:example:123", 1, "monthly", 100, 30);
    const result = contract.deactivateMembership("did:example:123", 1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const membership = contract.getMembership("did:example:123", 1);
    expect(membership?.active).toBe(false);
  });

  it("rejects unauthorized plan update", () => {
    contract.registerMembership("did:example:123", 1, "monthly", 100, 30);
    contract.caller = "ST2FAKE";
    const result = contract.updateMembershipPlan(
      "did:example:123",
      1,
      "yearly"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("rejects invalid DID", () => {
    const result = contract.registerMembership("short", 1, "monthly", 100, 30);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_DID);
  });

  it("rejects invalid gym ID", () => {
    const result = contract.registerMembership(
      "did:example:123",
      0,
      "monthly",
      100,
      30
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_GYM_ID);
  });

  it("rejects invalid plan", () => {
    const result = contract.registerMembership(
      "did:example:123",
      1,
      "invalid",
      100,
      30
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_PLAN);
  });

  it("rejects invalid start time", () => {
    const result = contract.registerMembership(
      "did:example:123",
      1,
      "monthly",
      50,
      30
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_START_TIME);
  });

  it("rejects max memberships exceeded", () => {
    contract.state.maxMemberships = 0;
    const result = contract.registerMembership(
      "did:example:123",
      1,
      "monthly",
      100,
      30
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_MEMBERSHIPS_EXCEEDED);
  });

  it("returns correct membership count", () => {
    contract.registerMembership("did:example:123", 1, "monthly", 100, 30);
    contract.registerMembership("did:example:456", 2, "yearly", 100, 365);
    const result = contract.getMembershipCount();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });
});
