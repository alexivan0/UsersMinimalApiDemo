
import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { User, LoginResponse } from './models';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private http = inject(HttpClient);
  private baseUrl = 'https://localhost:50886';

  private get headers() {
    const token = localStorage.getItem('token');
    return new HttpHeaders(token ? { Authorization: `Bearer ${token}` } : {});
  }

  login(email: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.baseUrl}/api/auth/login`, { email, password });
  }

  me() {
    return this.http.get<User>(`${this.baseUrl}/api/me`, { headers: this.headers });
  }

  listUsers() {
    return this.http.get<User[]>(`${this.baseUrl}/api/users`, { headers: this.headers });
  }

  createUser(payload: { fullName: string; email: string; password: string; role: string; status: string }) {
    return this.http.post<User>(`${this.baseUrl}/api/users`, payload, { headers: this.headers });
  }

  updateUser(id: string, payload: { fullName: string; email: string; password?: string; role: string; status: string }) {
    return this.http.put<User>(`${this.baseUrl}/api/users/${id}`, payload, { headers: this.headers });
  }

  deleteUser(id: string) {
    return this.http.delete(`${this.baseUrl}/api/users/${id}`, { headers: this.headers });
  }
}
