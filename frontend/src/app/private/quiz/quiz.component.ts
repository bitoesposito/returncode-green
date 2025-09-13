import { CommonModule } from '@angular/common';
import { Component, OnInit, OnDestroy } from '@angular/core';
import { FormArray, FormControl, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { TranslateModule, TranslateService } from '@ngx-translate/core';
import { ButtonModule } from 'primeng/button';
import { MessageService } from 'primeng/api';
import { ToastModule } from 'primeng/toast';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { DialogModule } from 'primeng/dialog';
import { CertificateService, GenerateCertificateRequest } from '../../services/certificate.service';
import { CookieAuthService } from '../../services/cookie-auth.service';
import { FullscreenService } from '../../services/fullscreen.service';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-quiz',
  imports: [
    ReactiveFormsModule,
    TranslateModule,
    CommonModule,
    FormsModule,
    ButtonModule,
    RouterModule,
    ToastModule,
    ProgressSpinnerModule,
    DialogModule
  ],
  templateUrl: './quiz.component.html',
  styleUrl: './quiz.component.scss',
  providers: [MessageService]
})
export class QuizComponent implements OnInit, OnDestroy {

  isQuizComplete = false;
  isLoading = false;
  currentUser: any = null;
  
  // Proprietà per il sistema fullscreen
  isFullscreenRequired = false;
  isFullscreenActive = false;
  showFullscreenDialog = false;
  private fullscreenSubscription?: Subscription;

  constructor(
    public router: Router,
    private certificateService: CertificateService,
    private authService: CookieAuthService,
    private messageService: MessageService,
    private fullscreenService: FullscreenService,
    private translate: TranslateService
  ) {}

  ngOnInit() {
    // Ottieni l'utente corrente
    this.authService.getCurrentUser().subscribe({
      next: (response: any) => {
        if (response.success && response.data?.user) {
          this.currentUser = response.data.user;
        }
      },
      error: (error: any) => {
        console.error('Errore nel recupero utente:', error);
        this.messageService.add({
          severity: 'error',
          summary: this.translate.instant('common.error'),
          detail: this.translate.instant('common.error')
        });
      }
    });

    // Attiva il fullscreen obbligatorio per il quiz
    this.startQuizFullscreen();
  }

  ngOnDestroy() {
    // Disattiva il fullscreen obbligatorio e pulisci le subscription
    this.stopQuizFullscreen();
    if (this.fullscreenSubscription) {
      this.fullscreenSubscription.unsubscribe();
    }
  }

  /**
   * Avvia il sistema di fullscreen obbligatorio per il quiz
   */
  private startQuizFullscreen(): void {
    this.isFullscreenRequired = true;
    this.fullscreenService.enableRequiredFullscreen();
    
    // Sottoscrivi ai cambiamenti di stato del fullscreen
    this.fullscreenSubscription = this.fullscreenService.isFullscreen$.subscribe(isFullscreen => {
      this.isFullscreenActive = isFullscreen;
      
      if (this.isFullscreenRequired && !isFullscreen) {
        // Se il fullscreen è richiesto ma non attivo, mostra il dialog
        this.showFullscreenDialog = true;
      } else {
        // Se il fullscreen è attivo, nascondi il dialog
        this.showFullscreenDialog = false;
      }
    });

    // Richiedi il fullscreen immediatamente
    this.requestFullscreen();
  }

  /**
   * Ferma il sistema di fullscreen obbligatorio
   */
  private stopQuizFullscreen(): void {
    this.isFullscreenRequired = false;
    this.showFullscreenDialog = false;
    this.fullscreenService.disableRequiredFullscreen();
  }

  /**
   * Richiede l'attivazione del fullscreen
   */
  async requestFullscreen(): Promise<void> {
    const success = await this.fullscreenService.requestFullscreen();
    if (!success) {
      this.messageService.add({
        severity: 'warn',
        summary: this.translate.instant('notification.warning'),
        detail: this.translate.instant('quiz.warnings.fullscreen-not-supported')
      });
    }
  }

  /**
   * Gestisce il click sul pulsante per attivare il fullscreen
   */
  onActivateFullscreen(): void {
    this.requestFullscreen();
  }

  /**
   * Genera certificato per il corso completato
   */
  generateCertificate() {
    if (!this.currentUser) {
      this.messageService.add({
        severity: 'error',
        summary: this.translate.instant('common.error'),
        detail: this.translate.instant('quiz.errors.user-not-found')
      });
      return;
    }

    this.isLoading = true;

    const certificateData: GenerateCertificateRequest = {
      user_uuid: this.currentUser.uuid,
      course_name: 'TypeScript Fundamentals Course',
      description: 'Corso completo sui fondamenti di TypeScript, incluse le funzionalità avanzate e le best practices per lo sviluppo moderno.',
      issued_date: new Date().toISOString(),
      metadata: {
        course_type: 'online',
        difficulty_level: 'intermediate',
        completion_score: 100,
        duration_hours: 20,
        instructor: 'ReturnCode Academy',
        quiz_score: '10/10',
        completion_date: new Date().toISOString()
      }
    };

    this.certificateService.generateCertificate(certificateData).subscribe({
      next: (certificate) => {
        this.isLoading = false;
        this.messageService.add({
          severity: 'success',
          summary: this.translate.instant('quiz.success.certificate-generated'),
          detail: this.translate.instant('quiz.success.certificate-redirect')
        });
        
        // Scarica il certificato e reindirizza alla home dopo 5 secondi
        this.downloadCertificate(certificate.id);
        setTimeout(() => {
          this.router.navigate(['/']);
        }, 4000);
      },
      error: (error) => {
        this.isLoading = false;
        console.error('Errore nella generazione certificato:', error);
        this.messageService.add({
          severity: 'error',
          summary: this.translate.instant('common.error'),
          detail: this.translate.instant('quiz.errors.certificate-generation-failed')
        });
      }
    });
  }

  /**
   * Scarica il certificato generato
   */
  private downloadCertificate(certificateId: string) {
    this.certificateService.downloadCertificateFile(certificateId);
  }

  checkAnswer(answer: number) {
    // Blocca l'input se non in fullscreen
    if (this.isFullscreenRequired && !this.isFullscreenActive) {
      this.messageService.add({
        severity: 'warn',
        summary: this.translate.instant('notification.warning'),
        detail: this.translate.instant('quiz.errors.fullscreen-required')
      });
      return;
    }

    if (answer === 3) {
      this.isQuizComplete = true;
      // Disattiva il fullscreen obbligatorio quando il quiz è completato
      this.stopQuizFullscreen();
    } else {
      this.messageService.add({
        severity: 'error',
        summary: this.translate.instant('common.error'),
        detail: this.translate.instant('quiz.errors.wrong-answer')
      });
    }
  }
}
