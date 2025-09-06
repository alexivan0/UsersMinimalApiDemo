
export type Role = 'Admin' | 'User';
export type Status = 'Active' | 'Inactive';

export interface User {
  id: string;
  fullName: string;
  email: string;
  role: Role;
  status: Status;
  createdAt: string;
  createdBy: string;
  modifiedAt?: string;
  modifiedBy?: string;
}

export interface LoginResponse {
  token: string;
  user: User;
}
