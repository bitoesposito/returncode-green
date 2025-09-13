import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { MessageService } from 'primeng/api';
import { ButtonModule } from 'primeng/button';
import { CheckboxModule } from 'primeng/checkbox';
import { InputTextModule } from 'primeng/inputtext';
import { PasswordModule } from 'primeng/password';
import { RippleModule } from 'primeng/ripple';
import { ToastModule } from 'primeng/toast';
import { TooltipModule } from 'primeng/tooltip';
import { NotificationService } from '../../../services/notification.service';
import { CookieAuthService } from '../../../services/cookie-auth.service';
import { finalize } from 'rxjs';
import { ThemeService } from '../../../services/theme.service';
import { Language, TranslateModule, TranslateService } from '@ngx-translate/core';
import { Observable } from 'rxjs';
import { SelectModule } from 'primeng/select';
import { LanguageService } from '../../../services/language.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    ButtonModule, 
    CheckboxModule, 
    InputTextModule, 
    PasswordModule, 
    FormsModule, 
    RouterModule, 
    RippleModule,
    CommonModule,
    ToastModule,
    ReactiveFormsModule,
    TranslateModule,
    TooltipModule,
    SelectModule
  ],
  providers: [
    MessageService,
    NotificationService,
    TranslateService
  ],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss'
})
export class LoginComponent implements OnInit {
  loading = false;
  socialLoading = false;
  isDarkMode$: Observable<boolean>;
  focusPassword = false;

  form: FormGroup = new FormGroup({
    email: new FormControl(null, [Validators.pattern(/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$/)]),
    password: new FormControl(null, [
      Validators.required,
      Validators.pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/)
    ]),
    rememberMe: new FormControl(false, [])
  });

  constructor(
    private notificationService: NotificationService,
    private router: Router,
    private authService: CookieAuthService,
    private themeService: ThemeService,
    private translate: TranslateService,
    private languageService: LanguageService
  ) {
    this.isDarkMode$ = this.themeService.isDarkMode$;
  }

  /**
   * Initializes the component and checks for email in the URL.
   */
  ngOnInit() {
    this.checkEmailFromUrl();
    setTimeout(() => {
      this.checkNotifications();
    }, 100);
  }

  /**
   * Checks the URL for an email parameter and updates the form.
   */
  private checkEmailFromUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    const email = urlParams.get('email');
    
    if (email) {
      this.form.patchValue({ email });
      this.focusPassword = true;
    } else {
      this.focusPassword = false;
    }
  }

  /**
   * Checks for notifications related to password reset and displays them.
   */
  private checkNotifications() {
    const showNotification = localStorage.getItem('show_password_reset_notification');
    if (showNotification === 'true') {
      this.notificationService.handleSuccess(this.translate.instant('auth.login.password-reset-success'));
      localStorage.removeItem('show_password_reset_notification');
    }
  }

  get email(): FormControl {
    return this.form.get('email') as FormControl;
  }

  get password(): FormControl {
    return this.form.get('password') as FormControl;
  }

  get rememberMe(): FormControl {
    return this.form.get('rememberMe') as FormControl;
  }

  /**
   * Handles the login process, including form validation and API interaction.
   */
  login() {
    if (this.form.invalid) {
      this.notificationService.handleWarning(this.translate.instant('auth.login.fill-required-fields'));
      return;
    }

    this.loading = true;
    // Disables all controls during loading
    this.form.disable();
    
    // Clear any cached data from previous sessions before login
    this.authService.clearAllAuthData();
    
    const credentials = {
      email: this.email.value,
      password: this.password.value,
      rememberMe: this.rememberMe.value
    };

    this.authService.login(credentials)
      .pipe(
        finalize(() => {
          this.loading = false;
          // Re-enables all controls after loading
          this.form.enable();
        })
      )
      .subscribe({
        next: (response: any) => {
          this.notificationService.handleApiResponse(response, this.translate.instant('auth.login.login-failed'));
          if (response.success && response.data) {
            // Set authentication status (tokens are in httpOnly cookies)
            this.authService.setAuthStatus('authenticated');
            // Dopo login, aggiorna lo stato utente SOLO con la risposta di /auth/me
            this.authService.forceRefreshUserData().subscribe({
              next: (data) => {
                // (opzionale) puoi salvare user/profile in uno stato globale se serve
                // Poi redirect
                window.location.href = '/';
              },
              error: () => {
                // Anche in caso di errore, redirect per forzare reload
                window.location.href = '/';
              }
            });
          }
        },
        error: (error: any) => {
          this.notificationService.handleError(error, this.translate.instant('auth.login.login-error'));
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
   * Toggles the remember me setting.
   */
  toggleRememberMe() {
    const currentValue = this.rememberMe.value;
    this.rememberMe.setValue(!currentValue);
  }

  /**
   * Placeholder for Google login functionality.
   */
  loginWithGoogle(event?: Event) {
    this.socialLoading = false;
    this.notificationService.handleInfo(this.translate.instant('auth.login.google-login-coming-soon'));
  }
  
  /**
   * Placeholder for Apple login functionality.
   */
  loginWithApple(event?: Event) {
    this.socialLoading = false;
    this.notificationService.handleInfo(this.translate.instant('auth.login.apple-login-coming-soon'));
  }

  
}