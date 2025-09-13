import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LoginComponent } from './components/login/login.component';
import { RecoverComponent } from './components/recover/recover.component';
import { VerifyComponent } from './components/verify/verify.component';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { InputTextModule } from 'primeng/inputtext';
import { ButtonModule } from 'primeng/button';
import { ToastModule } from 'primeng/toast';
import { PublicRoutingModule } from './public-routing.module';
import { TranslateModule } from '@ngx-translate/core';
import { RegisterComponent } from './components/register/register.component';

@NgModule({
  declarations: [],
  imports: [
    CommonModule,
    PublicRoutingModule,
    LoginComponent,
    RecoverComponent,
    VerifyComponent,
    RegisterComponent,
    ReactiveFormsModule,
    FormsModule,
    InputTextModule,
    ButtonModule,
    ToastModule,
    TranslateModule
  ],
  providers: []
})
export class PublicModule { } 