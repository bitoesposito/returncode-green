import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormControl, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { MessageService } from 'primeng/api';
import { ButtonModule } from 'primeng/button';
import { InputTextModule } from 'primeng/inputtext';
import { RippleModule } from 'primeng/ripple';
import { ToastModule } from 'primeng/toast';
import { TooltipModule } from 'primeng/tooltip';
import { NotificationService } from '../../../services/notification.service';
import { AuthService } from '../../../services/auth.service';
import { finalize, Observable } from 'rxjs';
import { ThemeService } from '../../../services/theme.service';
import { TranslateModule, TranslateService } from '@ngx-translate/core';
import { CookieAuthService } from '../../../services/cookie-auth.service';

@Component({
  selector: 'app-recover',
  standalone: true,
  imports: [
    ButtonModule,
    InputTextModule,
    FormsModule,
    RouterModule,
    RippleModule,
    CommonModule,
    ToastModule,
    ReactiveFormsModule,
    TranslateModule,
    TooltipModule
  ],
  providers: [
    MessageService,
    NotificationService
  ],
  templateUrl: './recover.component.html',
  styleUrl: './recover.component.scss'
})
export class RecoverComponent {
  loading = false;
  isDarkMode$: Observable<boolean>;

  form: FormGroup = new FormGroup({
    email: new FormControl(null, [
      Validators.required,
      Validators.pattern(/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$/)
    ])
  });

  constructor(
    private notificationService: NotificationService,
    private router: Router,
    private authService: CookieAuthService,
    private themeService: ThemeService,
    private translate: TranslateService
  ) {
    this.isDarkMode$ = this.themeService.isDarkMode$;
  }

  get email(): FormControl {
    return this.form.get('email') as FormControl;
  }

  /**
   * Handles the password recovery process, including form validation and API interaction.
   */
  recover() {
    if (this.form.invalid) {
      this.notificationService.handleWarning(this.translate.instant('auth.recover.fill-required-fields'));
      return;
    }

    this.loading = true;
    this.form.disable();
    
    const data = {
      email: this.email.value
    };

    this.authService.forgotPassword(data)
      .pipe(
        finalize(() => {
          this.loading = false;
          this.form.enable();
        })
      )
      .subscribe({
        next: (response: any) => {
          if (response.success) {
            this.notificationService.handleSuccess(this.translate.instant('auth.recover.recovery-sent'));
            this.router.navigate(['/reset'], { 
              queryParams: { email: this.email.value } 
            });
          } else {
            this.notificationService.handleWarning(response.message || this.translate.instant('auth.recover.recovery-failed'));
          }
        },
        error: (error: any) => {
          this.notificationService.handleError(error, this.translate.instant('auth.recover.recovery-error'));
        }
      });
  }

  /**
   * Toggles the dark mode setting.
   */
  toggleDarkMode() {
    this.themeService.toggleDarkMode();
  }
}
