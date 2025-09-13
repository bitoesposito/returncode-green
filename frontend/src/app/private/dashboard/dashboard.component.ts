import { Component, OnInit } from '@angular/core';
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
import { CertificateService, CertificateResponse } from '../../services/certificate.service';
import { CardModule } from 'primeng/card';
import { ButtonModule } from 'primeng/button';
import { TagModule } from 'primeng/tag';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { DividerModule } from 'primeng/divider';

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
    CourseCardsComponent,
    CardModule,
    ButtonModule,
    TagModule,
    ProgressSpinnerModule,
    DividerModule
  ],
  providers: [
    MessageService,
    NotificationService
  ],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss'
})
export class DashboardComponent implements OnInit {

  // Observable streams for reactive UI updates
  isDarkMode$;
  
  // Certificate properties
  certificates: CertificateResponse[] = [];
  isLoadingCertificates = false;
  isVerifyingCertificate = false;
  currentUser: any = null;

  constructor(
    private notificationService: NotificationService,
    private themeService: ThemeService,
    private translate: TranslateService,
    public router: Router,
    private certificateService: CertificateService,
    private authService: CookieAuthService,
    private messageService: MessageService
  ) {
    // Initialize observable streams
    this.isDarkMode$ = this.themeService.isDarkMode$;
    
    // Setup PWA functionality
    this.initializePWA();
  }

  ngOnInit() {
    this.loadUserCertificates();
  }

  /**
   * Carica i certificati dell'utente corrente
   */
  loadUserCertificates() {
    this.isLoadingCertificates = true;
    
    this.authService.getCurrentUser().subscribe({
      next: (response: any) => {
        if (response.success && response.data?.user?.uuid) {
          this.currentUser = response.data.user;
          
          this.certificateService.getUserCertificates(response.data.user.uuid).subscribe({
            next: (certificates: CertificateResponse[]) => {
              this.certificates = certificates;
              this.isLoadingCertificates = false;
            },
            error: (error: any) => {
              this.isLoadingCertificates = false;
              this.messageService.add({
                severity: 'error',
                summary: 'Errore',
                detail: 'Impossibile caricare i certificati: ' + (error.message || 'Errore sconosciuto')
              });
            }
          });
        } else {
          this.isLoadingCertificates = false;
        }
      },
      error: (error: any) => {
        this.isLoadingCertificates = false;
        this.messageService.add({
          severity: 'error',
          summary: 'Errore',
          detail: 'Impossibile recuperare i dati utente'
        });
      }
    });
  }

  /**
   * Scarica un certificato
   */
  downloadCertificate(certificateId: string) {
    this.certificateService.downloadCertificateFile(certificateId);
  }

  /**
   * Verifica un certificato e mostra il risultato in un toast
   */
  verifyCertificate(certificateId: string) {
    this.isVerifyingCertificate = true;

    this.certificateService.verifyCertificate(certificateId).subscribe({
      next: (response) => {
        this.isVerifyingCertificate = false;
        
        if (response.valid) {
          this.messageService.add({
            severity: 'success',
            summary: 'Certificato Valido',
            detail: 'Il certificato è autentico e non è stato modificato.',
            life: 5000
          });
        } else {
          this.messageService.add({
            severity: 'error',
            summary: 'Certificato Non Valido',
            detail: 'Il certificato non è autentico o è stato modificato.',
            life: 5000
          });
        }
      },
      error: (error) => {
        this.isVerifyingCertificate = false;
        this.messageService.add({
          severity: 'error',
          summary: 'Errore Verifica',
          detail: 'Impossibile verificare il certificato: ' + (error.message || 'Errore sconosciuto'),
          life: 5000
        });
      }
    });
  }

  /**
   * Formatta la data per la visualizzazione
   */
  formatDate(date: Date | string): string {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    return dateObj.toLocaleDateString('it-IT', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  }

  /**
   * Converte file_size in numero e calcola KB
   */
  getFileSizeInKB(fileSize: string | number): string {
    const size = typeof fileSize === 'string' ? Number(fileSize) : fileSize;
    return (size / 1024).toFixed(1);
  }

  /**
   * Ottieni il colore del tag in base allo stato del certificato
   */
  getCertificateStatusColor(certificate: CertificateResponse): string {
    return certificate.revoked ? 'danger' : 'success';
  }

  /**
   * Ottieni il testo dello stato del certificato
   */
  getCertificateStatusText(certificate: CertificateResponse): string {
    return certificate.revoked ? 'Revocato' : 'Valido';
  }

  /**
   * Ottieni la classe CSS per lo stato del certificato (stile course-cards)
   */
  getCertificateStatusClass(certificate: CertificateResponse): string {
    return certificate.revoked ? 'certificate-status-revoked' : 'certificate-status-valid';
  }


  /**
   * Initialize PWA-related functionality
   * Sets up listeners for app updates and online/offline status
   */
  private initializePWA(): void {
  }
}
