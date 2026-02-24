import type { UserRow } from "./db";

export const publicUser = (user: UserRow) => ({
  id: user.id,
  email: user.email,
  fullName: user.full_name,
  imageUrl: user.image_url,
  emailVerified: Boolean(user.email_verified),
  createdAt: user.created_at,
  updatedAt: user.updated_at
});

export const appendQuery = (target: string, key: string, value: string): string => {
  const url = new URL(target);
  url.searchParams.set(key, value);
  return url.toString();
};
