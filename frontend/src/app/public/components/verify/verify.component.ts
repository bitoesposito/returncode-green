import { CommonModule } from '@angular/common';
import { Component, OnInit, OnDestroy } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ConfirmationService, MessageService } from 'primeng/api';
import { ButtonModule } from 'primeng/button';
import { ToastModule } from 'primeng/toast';
import { Router, RouterModule } from '@angular/router';
import { NotificationService } from '../../../services/notification.service';
import { AuthService } from '../../../services/auth.service';
import { finalize } from 'rxjs';
import { ThemeService } from '../../../services/theme.service';
import { TranslateModule, TranslateService } from '@ngx-translate/core';
import { InputOtp } from 'primeng/inputotp';
import { Observable } from 'rxjs';
import { CookieAuthService } from '../../../services/cookie-auth.service';

@Component({
  selector: 'app-verify',
  standalone: true,
  imports: [
    ButtonModule,
    RouterModule,
    CommonModule,
    ToastModule,
    ReactiveFormsModule,
    TranslateModule,
    InputOtp
  ],
  providers: [
    ConfirmationService,
    MessageService,
    NotificationService
  ],
  templateUrl: './verify.component.html',
  styleUrl: './verify.component.scss'
})
export class VerifyComponent implements OnInit, OnDestroy {
  loading = false; 
  verifying = false;
  verificationAttempted = false;
  isDarkMode$: Observable<boolean>;
  resendTimer = 0;
  resendDisabled = false;
  private timerInterval: any;
  userEmail: string = '';

  form: FormGroup = new FormGroup({
    token: new FormControl(null, [Validators.required])
  })

  constructor(
    private notificationService: NotificationService,
    private router: Router,
    private authService: CookieAuthService,
    private themeService: ThemeService,
    private translate: TranslateService
  ) {
    this.isDarkMode$ = this.themeService.isDarkMode$;
  }

  ngOnInit() {
    this.checkTokenFromUrl();
    this.checkEmailFromUrl();
    this.initializeResendTimer();
    this.setupAutoSubmit();
  }

  ngOnDestroy() {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
    }
    localStorage.removeItem('last_resend_time');
  }

  /**
   * Checks URL parameters to retrieve the user's email.
   */
  private checkEmailFromUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    const email = urlParams.get('email');
    
    if (email) {
      this.userEmail = email;
    }
  }

  /**
   * Initializes the resend timer based on the last resend time stored in local storage.
   */
  private initializeResendTimer() {
    const lastResendTime = localStorage.getItem('last_resend_time');
    const currentTime = Date.now();
    
    if (lastResendTime) {
      const timeElapsed = Math.floor((currentTime - parseInt(lastResendTime)) / 1000);
      const remainingTime = Math.max(0, 60 - timeElapsed);
      
      if (remainingTime > 0) {
        this.resendTimer = remainingTime;
        this.resendDisabled = true;
        this.startTimer();
      } else {
        this.resendTimer = 0;
        this.resendDisabled = false;
        localStorage.removeItem('last_resend_time');
      }
    } else {
      // If no previous resend time, start the timer immediately since email was sent during registration
      this.resendTimer = 60;
      this.resendDisabled = true;
      localStorage.setItem('last_resend_time', Date.now().toString());
      this.startTimer();
    }
  }

  /**
   * Starts the resend timer countdown.
   */
  private startTimer() {
    this.timerInterval = setInterval(() => {
      this.resendTimer--;
      
      if (this.resendTimer <= 0) {
        this.resendTimer = 0;
        this.resendDisabled = false;
        localStorage.removeItem('last_resend_time');
        clearInterval(this.timerInterval);
      }
    }, 1000);
  }

  /**
   * Resends the verification code to the user's email.
   */
  resendCode() {
    if (this.resendDisabled || !this.userEmail) return;

    this.resendDisabled = true;
    this.resendTimer = 60;
    localStorage.setItem('last_resend_time', Date.now().toString());
    
    this.startTimer();
    
    this.authService.resendVerification({ email: this.userEmail })
      .subscribe({
        next: (response: any) => {
          if (response.success) {
            this.notificationService.handleSuccess(this.translate.instant('auth.verify.resend-code-sent'));
          } else {
            this.notificationService.handleWarning(response.message || this.translate.instant('auth.verify.resend-code-failed'));
          }
        },
        error: (error: any) => {
          this.notificationService.handleError(error, this.translate.instant('auth.verify.resend-code-error'));
        }
      });
  }

  /**
   * Retrieves the label for the resend button, including the countdown timer if applicable.
   */
  getResendButtonLabel(): string {
    if (this.resendDisabled && this.resendTimer > 0) {
      return `${this.translate.instant('auth.verify.resend-code')} (${this.resendTimer}s)`;
    }
    return this.translate.instant('auth.verify.resend-code');
  }

  /**
   * Checks URL parameters to retrieve the verification token.
   */
  private checkTokenFromUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    if (token) {
      this.form.patchValue({ token });
    }
  }

  get token(): FormControl {
    return this.form.get('token') as FormControl
  }

  /**
   * Initiates the email verification process, including form validation and API interaction.
   */
  verify() {
    if (this.form.invalid || this.verifying) {
      this.notificationService.handleWarning(this.translate.instant('auth.verify.fill-required-fields'));
      return;
    }

    // Additional check to prevent multiple calls
    if (this.verifying) {
      return;
    }

    this.verifying = true;
    this.verificationAttempted = true;
    // Disable all controls during verification
    this.form.disable();

    const data = {
      token: this.token.value
    };

    // Add minimum delay of 1 second for better UX
    const startTime = Date.now();
    const minDelay = 1000; // 1 second

    this.authService.verifyEmail(data)
      .pipe(
        finalize(() => {
          // Do not re-enable the form here, only do so in case of error
        })
      )
      .subscribe({
        next: (response: any) => {
          if (response.success) {
            this.notificationService.handleSuccess(this.translate.instant('auth.verify.success'));
            localStorage.removeItem('last_resend_time');
            // Block the form and prevent further verifications
            this.form.disable();
            this.verifying = true;
            this.verificationAttempted = true;
            // Redirect after toast
            setTimeout(() => {
              this.router.navigate(['/login'], { 
                queryParams: { email: this.userEmail } 
              });
            }, 2000);
          } else {
            this.notificationService.handleWarning(response.message || this.translate.instant('auth.verify.verification-failed'));
            // Re-enable the form only in case of error
            this.form.enable();
            this.verifying = false;
            this.verificationAttempted = false;
          }
        },
        error: (error: any) => {
          this.notificationService.handleError(error, this.translate.instant('auth.verify.verification-error'));
          // Re-enable the form only in case of error
          this.form.enable();
          this.verifying = false;
          this.verificationAttempted = false;
        }
      });
  }

  toggleDarkMode() {
    this.themeService.toggleDarkMode();
  }

  onPaste(event: ClipboardEvent) {
    event.preventDefault();
    
    const clipboardData = event.clipboardData;
    if (!clipboardData) return;
    
    const pastedText = clipboardData.getData('text');
    if (!pastedText) return;
    
    // Extract only numbers from pasted text
    const numbers = pastedText.replace(/\D/g, '').slice(0, 6);
    
    if (numbers.length === 6) {
      // Temporarily disable auto-submit
      this.verificationAttempted = true;
      
      this.form.patchValue({ token: numbers });
      
      // Re-enable auto-submit after a brief delay
      setTimeout(() => {
        this.verificationAttempted = false;
        // If the form is valid, proceed with verification
        if (this.form.valid && !this.verifying) {
          this.verify();
        }
      }, 200);
    }
  }

  private setupAutoSubmit() {
    this.form.get('token')?.valueChanges.subscribe((value: string) => {
      if (value && value.length === 6 && !this.verifying && !this.verificationAttempted) {
        // Auto-submit when OTP is complete and no verification was attempted yet
        setTimeout(() => {
          if (this.form.valid && !this.verifying) {
            this.verify();
          }
        }, 100); // Small delay to ensure the value is properly set
      }
    });
  }
}
