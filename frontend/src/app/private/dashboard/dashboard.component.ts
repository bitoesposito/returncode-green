import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { NotificationService } from '../../services/notification.service';
import { ToastModule } from 'primeng/toast';
import { ThemeService } from '../../services/theme.service';
import { TranslateModule, TranslateService } from '@ngx-translate/core';
import { AuthService } from '../../services/auth.service';
import { NavBarComponent } from '../nav-bar/nav-bar.component';
import { MessageService } from 'primeng/api';
import { CookieAuthService } from '../../services/cookie-auth.service';
import { CourseCardsComponent } from '../../shared/course-cards/course-cards.component';

/**
 * Dashboard Component
 * 
 * Main dashboard page for authenticated users.
 * Handles PWA updates and online/offline status notifications.
 */
@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [
    CommonModule,
    ToastModule,
    TranslateModule,
    NavBarComponent,
    RouterModule,
    CourseCardsComponent
  ],
  providers: [
    MessageService,
    NotificationService
  ],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss'
})
export class DashboardComponent {

  // Observable streams for reactive UI updates
  isDarkMode$;

  constructor(
    private notificationService: NotificationService,
    private themeService: ThemeService,
    private translate: TranslateService,
    private router: Router
  ) {
    // Initialize observable streams
    this.isDarkMode$ = this.themeService.isDarkMode$;
    
    // Setup PWA functionality
    this.initializePWA();
  }

  /**
   * Initialize PWA-related functionality
   * Sets up listeners for app updates and online/offline status
   */
  private initializePWA(): void {
  }
}
