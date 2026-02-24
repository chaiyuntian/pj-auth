import {
  listApplicableOrganizationPolicies,
  type OrganizationPolicyRow,
  type OrganizationRole
} from "./db";

export type OrganizationPermission = {
  resource: string;
  action: string;
};

export type OrganizationPermissionEvaluation = {
  allowed: boolean;
  source: "base" | "policy_allow" | "policy_deny";
  policy?: OrganizationPolicyRow;
};

const keyFor = (permission: OrganizationPermission): string =>
  `${permission.resource.trim().toLowerCase()}:${permission.action.trim().toLowerCase()}`;

const ownerPermissions = new Set<string>(["*:*"]);
const adminPermissions = new Set<string>([
  "org:read",
  "org:manage",
  "members:read",
  "members:manage",
  "teams:read",
  "teams:manage",
  "service_accounts:read",
  "service_accounts:manage",
  "webhooks:read",
  "webhooks:manage"
]);
const memberPermissions = new Set<string>(["org:read", "members:read", "teams:read"]);

const roleMatrix: Record<OrganizationRole, Set<string>> = {
  owner: ownerPermissions,
  admin: adminPermissions,
  member: memberPermissions
};

const hasPermission = (role: OrganizationRole, permission: OrganizationPermission): boolean => {
  const rolePermissions = roleMatrix[role];
  if (!rolePermissions) {
    return false;
  }
  if (rolePermissions.has("*:*")) {
    return true;
  }
  const exact = keyFor(permission);
  if (rolePermissions.has(exact)) {
    return true;
  }
  if (rolePermissions.has(`${permission.resource.toLowerCase()}:*`)) {
    return true;
  }
  return rolePermissions.has(`*:${permission.action.toLowerCase()}`);
};

export const evaluateOrganizationPermission = async (params: {
  db: D1Database;
  organizationId: string;
  userId: string;
  role: OrganizationRole;
  permission: OrganizationPermission;
}): Promise<OrganizationPermissionEvaluation> => {
  const resource = params.permission.resource.trim().toLowerCase();
  const action = params.permission.action.trim().toLowerCase();
  const baseAllowed = hasPermission(params.role, { resource, action });
  const applicable = await listApplicableOrganizationPolicies(params.db, {
    organizationId: params.organizationId,
    userId: params.userId,
    role: params.role,
    resource,
    action
  });

  const denyPolicy = applicable.find((policy) => policy.effect === "deny");
  if (denyPolicy) {
    return {
      allowed: false,
      source: "policy_deny",
      policy: denyPolicy
    };
  }

  const allowPolicy = applicable.find((policy) => policy.effect === "allow");
  if (allowPolicy) {
    return {
      allowed: true,
      source: "policy_allow",
      policy: allowPolicy
    };
  }

  return {
    allowed: baseAllowed,
    source: "base"
  };
};
