import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { ButtonModule } from 'primeng/button';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { ConfirmationService } from 'primeng/api';
import { NotificationService } from '../../services/notification.service';
import { ToastModule } from 'primeng/toast';
import { TooltipModule } from 'primeng/tooltip';
import { ThemeService } from '../../services/theme.service';
import { TranslateModule, TranslateService } from '@ngx-translate/core';
import { CookieAuthService } from '../../services/cookie-auth.service';
import { PopoverModule } from 'primeng/popover';

import { SelectModule } from 'primeng/select';
import { FormsModule } from '@angular/forms';
import { LanguageService } from '../../services/language.service';
import { Language } from '../../models/language.models';
import { UserData } from '../../models/auth.models';
import { Subject, takeUntil } from 'rxjs';

/**
 * NavBar Component
 * 
 * Main navigation bar component with user menu, language selector,
 * theme toggle, and PWA functionality.
 */
@Component({
  selector: 'app-nav-bar',
  standalone: true,
  imports: [
    ButtonModule,
    CommonModule,
    RouterModule,
    ToastModule,
    TooltipModule,
    TranslateModule,
    PopoverModule,
    SelectModule,
    FormsModule
  ],
  providers: [
    ConfirmationService
  ],
  templateUrl: './nav-bar.component.html',
  styleUrl: './nav-bar.component.scss'
})
export class NavBarComponent implements OnInit, OnDestroy {

  // Observable streams for reactive UI updates
  isDarkMode$;
  currentLanguage$;
  
  // User data from JWT token
  user: UserData | null = null;
  
  // Language selector properties
  languages: Language[] = [];
  selectedLanguage: string = 'en';

  // Destroy subject for proper cleanup
  private destroy$ = new Subject<void>();

  constructor(
    private notificationService: NotificationService,
    private router: Router,
    private themeService: ThemeService,
    private translate: TranslateService,
    private authService: CookieAuthService,
    private languageService: LanguageService,
    private cdr: ChangeDetectorRef
  ) {
    // Initialize observable streams
    this.isDarkMode$ = this.themeService.isDarkMode$;
    this.currentLanguage$ = this.languageService.currentLanguage$;
  }

  ngOnInit(): void {
    this.loadUserData();
    this.initializeLanguages();
    this.syncSelectedLanguage();
  }

  ngOnDestroy(): void {
    // Cleanup subscriptions to prevent memory leaks
    this.destroy$.next();
    this.destroy$.complete();
  }

  /**
   * Load user data from authentication service
   */
  private loadUserData(): void {
    // Handle user switching to ensure fresh data and proper cleanup
    this.authService.handleUserSwitch().subscribe({
      next: (response) => {
        if (response.data) {
          this.user = response.data.user;
          // Update authentication status
          this.authService.setAuthStatus('authenticated');
        }
      },
      error: (error) => {
        console.error('Error loading user data:', error);
        this.handleAuthError();
      }
    });
  }

  /**
   * Handle authentication errors by logging out user
   */
  private handleAuthError(): void {
    // Immediately clear user data and authentication state
    this.user = null;
    this.authService.forceLogout();
    this.router.navigate(['/login']);
  }

  /**
   * Initialize available languages for selector
   */
  private initializeLanguages(): void {
    this.languages = this.languageService.getAvailableLanguages();
    this.selectedLanguage = this.languageService.getCurrentLanguage();
  }

  /**
   * Sync selected language with language service
   */
  private syncSelectedLanguage(): void {
    this.currentLanguage$
      .pipe(takeUntil(this.destroy$))
      .subscribe((languageCode: string) => {
        this.selectedLanguage = languageCode;
        this.cdr.detectChanges();
      });
  }

  /**
   * Handle language change from selector
   */
  changeLanguage(event: { value: string }): void {
    const languageCode = event.value;
    this.languageService.changeLanguage(languageCode);
    this.selectedLanguage = languageCode;
  }

  /**
   * Logout user and redirect to login
   */
  disconnect(): void {
    this.user = null;
    this.authService.forceLogout();
    this.authService.logout().subscribe({
      next: () => this.router.navigate(['/login']),
      error: () => this.router.navigate(['/login'])
    });
  }

  /**
   * Toggle between light and dark theme
   */
  toggleDarkMode(): void {
    this.themeService.toggleDarkMode();
  }
}
