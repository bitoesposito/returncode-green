import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { RecoverComponent } from './components/recover/recover.component';
import { VerifyComponent } from './components/verify/verify.component';
import { ResetComponent } from './components/reset/reset.component';
import { authRedirectGuard } from '../guards/auth-redirect.guard';

const routes: Routes = [
  {
    path: 'login',
    component: LoginComponent,
    canActivate: [authRedirectGuard]
  },
  {
    path: 'register',
    component: RegisterComponent,
    canActivate: [authRedirectGuard]
  },
  {
    path: 'recover',
    component: RecoverComponent,
    canActivate: [authRedirectGuard]
  },
  {
    path: 'verify',
    component: VerifyComponent,
    canActivate: [authRedirectGuard]
  },
  {
    path: 'reset',
    component: ResetComponent,
    canActivate: [authRedirectGuard]
  },
  {
    path: '**',
    redirectTo: 'login',
    pathMatch: 'full'
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class PublicRoutingModule { } 