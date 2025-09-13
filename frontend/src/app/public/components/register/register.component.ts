import { CommonModule } from '@angular/common';
import { Component, OnInit, OnDestroy } from '@angular/core';
import { FormControl, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { MessageService } from 'primeng/api';
import { ButtonModule } from 'primeng/button';
import { InputTextModule } from 'primeng/inputtext';
import { PasswordModule } from 'primeng/password';
import { RippleModule } from 'primeng/ripple';
import { ToastModule } from 'primeng/toast';
import { TooltipModule } from 'primeng/tooltip';
import { NotificationService } from '../../../services/notification.service';
import { AuthService } from '../../../services/auth.service';
import { finalize, Observable, Subscription } from 'rxjs';
import { ThemeService } from '../../../services/theme.service';
import { TranslateModule, TranslateService } from '@ngx-translate/core';
import { CookieAuthService } from '../../../services/cookie-auth.service';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [
    ButtonModule, 
    InputTextModule, 
    PasswordModule, 
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
  templateUrl: './register.component.html',
  styleUrl: './register.component.scss'
})
export class RegisterComponent implements OnInit, OnDestroy {
  loading = false;
  socialLoading = false;
  isDarkMode$: Observable<boolean>;
  private subscription: Subscription = new Subscription();

  form: FormGroup = new FormGroup({
    email: new FormControl(null, [
      Validators.required,
      Validators.pattern(/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$/)
    ]),
    password: new FormControl(null, [
      Validators.required,
      Validators.pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/)
    ]),
    confirmPassword: new FormControl(null, [
      Validators.required
    ])
  });

  constructor(
    private notificationService: NotificationService,
    private router: Router,
    private authService: CookieAuthService,
    private themeService: ThemeService,
    private translate: TranslateService,
  ) {
    this.isDarkMode$ = this.themeService.isDarkMode$;
  }

  ngOnInit() {
    // Add password confirmation validation
    this.subscription.add(
      this.form.get('confirmPassword')?.valueChanges.subscribe(() => {
        this.validatePasswordConfirmation();
      })
    );
  }

  ngOnDestroy() {
    this.subscription.unsubscribe();
  }

  /**
   * Validates that the password and confirm password fields match.
   */
  private validatePasswordConfirmation() {
    const password = this.form.get('password')?.value;
    const confirmPassword = this.form.get('confirmPassword')?.value;
    
    if (password && confirmPassword && password !== confirmPassword) {
      this.form.get('confirmPassword')?.setErrors({ passwordMismatch: true });
    } else {
      this.form.get('confirmPassword')?.setErrors(null);
    }
  }

  get email(): FormControl {
    return this.form.get('email') as FormControl;
  }

  get password(): FormControl {
    return this.form.get('password') as FormControl;
  }

  get confirmPassword(): FormControl {
    return this.form.get('confirmPassword') as FormControl;
  }

  /**
   * Handles the registration process, including form validation and API interaction.
   */
  register() {
    if (this.form.invalid) {
      this.notificationService.handleWarning(this.translate.instant('auth.register.fill-required-fields'));
      return;
    }

    if (this.password.value !== this.confirmPassword.value) {
      this.notificationService.handleWarning(this.translate.instant('auth.register.passwords-not-match'));
      return;
    }

    this.loading = true;
    // Disables all controls during loading
    this.form.disable();
    
    const registrationData = {
      email: this.email.value,
      password: this.password.value
    };

    this.authService.register(registrationData)
      .pipe(
        finalize(() => {
          this.loading = false;
          // Re-enables all controls after loading
          this.form.enable();
        })
      )
      .subscribe({
        next: (response: any) => {
          if (response.success) {
            this.router.navigate(['/verify'], { queryParams: { email: this.email.value } });
          } else {
            this.notificationService.handleWarning(response.message || this.translate.instant('auth.register.registration-failed'));
          }
        },
        error: (error: any) => {
          this.notificationService.handleError(error, this.translate.instant('auth.register.registration-error'));
        }
      });
  }

  /**
   * Toggles the dark mode setting.
   */
  toggleDarkMode() {
    this.themeService.toggleDarkMode();
  }

  /**
   * Placeholder for Google registration functionality.
   */
  registerWithGoogle(event?: Event) {
    this.socialLoading = false;
    this.notificationService.handleInfo(this.translate.instant('auth.register.google-register-coming-soon'));
  }
  
  /**
   * Placeholder for Apple registration functionality.
   */
  registerWithApple(event?: Event) {
    this.socialLoading = false;
    this.notificationService.handleInfo(this.translate.instant('auth.register.apple-register-coming-soon'));
  }
}
