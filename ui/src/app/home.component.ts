
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from './api.service';
import { User } from './models';
import { RouterLink } from '@angular/router';
import { AuthService } from './auth.service';

@Component({
  standalone: true,
  selector: 'app-home',
  imports: [CommonModule, RouterLink],
  template: `
  <div class="wrap">
    <header>
      <h2>Home</h2>
      <nav>
        <a routerLink="/users" *ngIf="role==='Admin'">Users</a>
        <a (click)="logout()">Logout</a>
      </nav>
    </header>
    <div *ngIf="me">
      <p><b>FullName:</b> {{ me.fullName }}</p>
      <p><b>Email:</b> {{ me.email }}</p>
      <p><b>Role:</b> {{ me.role }}</p>
      <p><b>Status:</b> {{ me.status }}</p>
    </div>
  </div>`,
  styles: [`
    .wrap { max-width: 680px; margin: 40px auto; }
    header { display: flex; justify-content: space-between; align-items: center; }
    nav a { margin-left: 12px; cursor: pointer; }
  `]
})
export class HomeComponent implements OnInit {
  me?: User;
  role = localStorage.getItem('role') || 'User';

  constructor(private api: ApiService, private auth: AuthService) {}

  ngOnInit(): void {
    this.api.me().subscribe(u => this.me = u);
  }

  logout() { this.auth.logout(); }
}
