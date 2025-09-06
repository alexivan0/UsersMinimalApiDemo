
import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { ApiService } from './api.service';
import { tap } from 'rxjs/operators';

@Injectable({ providedIn: 'root' })
export class AuthService {
  constructor(private api: ApiService, private router: Router) {}

  login(email: string, password: string) {
    return this.api.login(email, password).pipe(
      tap(res => {
        localStorage.setItem('token', res.token);
        localStorage.setItem('role', res.user.role);
        localStorage.setItem('me', JSON.stringify(res.user));
        this.router.navigate(['/home']);
      })
    );
  }

  logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    localStorage.removeItem('me');
    this.router.navigate(['/login']);
  }

  get token() { return localStorage.getItem('token'); }
  get role() { return localStorage.getItem('role'); }
  get isLoggedIn() { return !!this.token; }
}
