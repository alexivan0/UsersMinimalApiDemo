
import { Routes } from '@angular/router';
import { LoginComponent } from './login.component';
import { HomeComponent } from './home.component';
import { UsersComponent } from './users.component';
import { authGuard } from './auth.guard';
import { roleGuard } from './role.guard';

export const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: 'home', component: HomeComponent, canActivate: [authGuard] },
  { path: 'users', component: UsersComponent, canActivate: [authGuard, roleGuard], data: { roles: ['Admin'] } },
  { path: '', pathMatch: 'full', redirectTo: 'login' },
  { path: '**', redirectTo: 'login' },
];
