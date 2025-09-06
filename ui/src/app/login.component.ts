
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { AuthService } from './auth.service';

@Component({
  standalone: true,
  selector: 'app-login',
  imports: [CommonModule, FormsModule],
  template: `
  <div class="container">
    <h2>Login</h2>
    <form (ngSubmit)="submit()">
      <label>Email</label>
      <input [(ngModel)]="email" name="email" type="email" required />
      <label>Password</label>
      <input [(ngModel)]="password" name="password" type="password" required />
      <button type="submit">Login</button>
      <p class="hint">Admin: admin@example.com / Admin123! &nbsp; | &nbsp; User: user@example.com / User123!</p>
    </form>
    <p class="error" *ngIf="error">{{ error }}</p>
  </div>`,
  styles: [`
    .container { max-width: 360px; margin: 80px auto; display: flex; flex-direction: column; gap: 8px; }
    input { width: 100%; padding: 8px; margin-bottom: 8px; }
    button { padding: 10px; }
    .error { color: red; }
    .hint { font-size: 12px; color: #444; }
  `]
})
export class LoginComponent {
  email = '';
  password = '';
  error = '';
  constructor(private auth: AuthService) {}

  submit() {
    this.error = '';
    this.auth.login(this.email, this.password).subscribe({ error: _ => this.error = 'Invalid credentials' });
  }
}
