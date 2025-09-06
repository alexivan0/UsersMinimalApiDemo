
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from './api.service';
import { User } from './models';
import { RouterLink } from '@angular/router';

@Component({
  standalone: true,
  selector: 'app-users',
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
  <div class="wrap">
    <header>
      <h2>Users</h2>
      <nav>
        <a routerLink="/home">Home</a>
      </nav>
    </header>

    <form class="card" (ngSubmit)="save()">
      <h3>{{ editingId ? 'Edit User' : 'Create User' }}</h3>
      <label>Full Name</label>
      <input [(ngModel)]="form.fullName" name="fullName" required minlength="2" maxlength="100" />

      <label>Email</label>
      <input [(ngModel)]="form.email" name="email" required type="email" />

      <label>Role</label>
      <select [(ngModel)]="form.role" name="role">
        <option>Admin</option>
        <option>User</option>
      </select>

      <label>Status</label>
      <select [(ngModel)]="form.status" name="status">
        <option>Active</option>
        <option>Inactive</option>
      </select>

      <label>Password <small *ngIf="editingId">(leave blank to keep)</small></label>
      <input [(ngModel)]="form.password" name="password" [required]="!editingId" type="password" />

      <button type="submit">{{ editingId ? 'Update' : 'Create'}}</button>
      <button type="button" (click)="reset()">Cancel</button>
      <p class="error" *ngIf="error">{{ error }}</p>
    </form>

    <table class="grid">
      <thead>
        <tr>
          <th>FullName</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr *ngFor="let u of users">
          <td>{{ u.fullName }}</td>
          <td>{{ u.email }}</td>
          <td>{{ u.role }}</td>
          <td>{{ u.status }}</td>
          <td>
            <button (click)="edit(u)">Edit</button>
            <button (click)="del(u)">Delete</button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
  `,
  styles: [`
    .wrap { max-width: 900px; margin: 30px auto; }
    header { display:flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
    .card { display:grid; grid-template-columns: 1fr 1fr; gap:10px; padding:14px; border: 1px solid #ddd; border-radius: 8px; margin-bottom: 20px; }
    .card h3 { grid-column: 1 / -1; margin: 0 0 6px 0; }
    .grid { width: 100%; border-collapse: collapse; }
    .grid th, .grid td { border: 1px solid #ddd; padding: 8px; }
    .grid th { background: #f8f8f8; }
    button { margin-right: 6px; }
    .error { color: red; grid-column: 1/-1; }
  `]
})
export class UsersComponent implements OnInit {
  users: User[] = [];
  editingId?: string;
  form: any = { fullName: '', email: '', password: '', role: 'User', status: 'Active' };
  error = '';

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.load();
  }

  load() {
    this.api.listUsers().subscribe(data => this.users = data);
  }

  edit(u: User) {
    this.editingId = u.id;
    this.form = { fullName: u.fullName, email: u.email, password: '', role: u.role, status: u.status };
  }

  reset() {
    this.editingId = undefined;
    this.form = { fullName: '', email: '', password: '', role: 'User', status: 'Active' };
    this.error = '';
  }

  save() {
    const p = { ...this.form };
    if (this.editingId) {
      if (!p.password) delete p.password;
      this.api.updateUser(this.editingId, p).subscribe({
        next: _ => { this.reset(); this.load(); },
        error: err => this.error = this.extract(err),
      });
    } else {
      this.api.createUser(p).subscribe({
        next: _ => { this.reset(); this.load(); },
        error: err => this.error = this.extract(err),
      });
    }
  }

  del(u: User) {
    if (!confirm(`Delete ${u.fullName}?`)) return;
    this.api.deleteUser(u.id).subscribe(_ => this.load());
  }

  extract(err: any) {
    try {
      const e = err.error;
      if (typeof e === 'string') return e;
      if (e?.error) return e.error;
      if (e?.errors) return e.errors.join('; ');
    } catch {}
    return 'Error';
  }
}
